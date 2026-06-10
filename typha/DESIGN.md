# Typha Design

This document records architecture invariants, design rationale, and review
criteria for the Typha component. It is updated alongside code changes — a PR
that changes behaviour, data model, configuration surface, or any invariant
recorded here must update the relevant section in the same PR.

## Overview

Typha is a fan-out caching proxy that sits between the Kubernetes API server
and the Felix agents (and other Calico components). It reduces API server load
by maintaining a single watch connection and serving a large number of clients
from its snapshot cache.

## Leader election

### Purpose

In hierarchical mode (see "Hierarchical mode" section, added by WS-A), exactly
one Typha instance sources its syncer pipelines from the real datastore — the
**leader**. All other Typhas source from the leader (or from tier-1 Typhas that
themselves source from the leader). Leader election coordinates which Typha
instance is the leader.

WS-B adds the election machinery. The result is inert until WS-C wires it to
promotion/demotion.

### Mechanism

Lease-based leader election via `k8s.io/client-go/tools/leaderelection` with a
`coordination.k8s.io/v1` Lease object. Kubernetes-datastore mode only — etcd
deployments do not support this feature.

Configuration parameters (all prefixed `TYPHA_`, env-var style):

| Parameter | Default | Meaning |
|---|---|---|
| `LeaderElectionEnabled` | false | Gates all election machinery |
| `LeaseName` | `calico-typha-leader` | Name of the Lease object |
| `LeaseNamespace` | value of `PodNamespace` | Namespace for the Lease |
| `LeaderElectionDuration` | 15s | `LeaseDuration` — how long a non-leader waits before forcing acquisition |
| `LeaderRenewDeadline` | 10s | `RenewDeadline` — how long the leader retries before giving up |
| `LeaderRetryPeriod` | 2s | `RetryPeriod` — polling interval |

The recommended client-go ratios are satisfied:
`LeaseDuration (15s) > RenewDeadline (10s) > RetryPeriod × JitterFactor (2s × 1.2 = 2.4s)`.

Pod identity is injected via downward-API environment variables
(`TYPHA_PODNAME`, `TYPHA_PODNAMESPACE`, `TYPHA_NODENAME`) set in the Helm
chart. The `Identity` field of the Lease record equals the pod name, which is
globally unique and stable across restarts.

### Best-effort guarantee and dual-leader window

**Client-go does not provide strict single-leader semantics.** The package
comment documents that the guarantee is "best-effort" and relies on bounded
clock skew. With the default parameters, two Typhas can simultaneously believe
they are leader for a window of up to `LeaseDuration` (15s) in pathological
clock-skew or API-partition scenarios.

**WS-C must tolerate dual-leader.** Two Typhas briefly running real datastore
syncers is safe: both serve correct data; the extra datastore load is transient
and bounded. Nothing in the design should corrupt state under dual-leadership
(e.g. no shared mutable state gated on "I am the unique leader").

### Re-election on leadership loss

The `Elector` wrapper (`typha/pkg/leaderelection`) does **not** exit on
leadership loss (unlike `RunOrDie`). Instead it emits `Follower` on the `Roles()`
channel and immediately re-enters the election loop. This means a demoted Typha
automatically becomes a candidate again without any external restart.

### Graceful handover (`ReleaseOnCancel`)

`ReleaseOnCancel: true` is set so that a Typha stopping cleanly (e.g. during a
rolling upgrade) releases the lease immediately rather than waiting for it to
expire. This keeps the leadership gap bounded to the time for another candidate
to detect and acquire the released lease (approximately `RetryPeriod`, i.e. 2s)
rather than `LeaseDuration` (15s).

WS-C must order lease release (context cancellation propagating to the elector)
**after** completing any in-flight work that requires leadership, and **before**
closing client connections, to avoid serving stale data from a demoted Typha.

### Per-lease instantiation

`Elector` is instantiated per Lease (the lease name is a Config parameter, not
a singleton). WS-E uses this to run N parallel electors for tier-1 slots, each
with its own Lease object.

### RBAC

The `calico-node` ClusterRole (shared with calico-node's ServiceAccount, which
Typha pods use) gets:

- `coordination.k8s.io/leases: create` — unrestricted (Kubernetes cannot scope
  `create` to `resourceNames`)
- `coordination.k8s.io/leases: get, update` — scoped to `calico-typha-leader`
  via `resourceNames`

If `LeaseName` is customised, the `resourceNames` restriction must be updated
accordingly (or removed if the operator cannot predict the name).

### Health and metrics

- Health reporter `"LeaderElection"` is registered on the `HealthAggregator`
  while the elector loop is running. Liveness only — readiness is not gated on
  holding the lease (a follower Typha is fully ready to serve cached data).
- `typha_leader` gauge: 1 when this instance holds the lease, 0 otherwise.
- `typha_leader_transitions_total` counter: increments on every
  Leader→Follower or Follower→Leader transition.
- `typha_leader_holder_info` gauge vec (label `holder`): info-style gauge,
  value always 1, label carries the current holder's pod-name identity.
