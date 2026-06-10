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

Operational guidance (build, test, debug) lives in `typha/CLAUDE.md` if
present; this document is the architecture and invariants reference. Read it
before changing how Typha sources, caches, or serves data.

## Architecture

### Syncer pipelines

Typha runs one independent **pipeline per syncer type**. There are four
(`syncproto.NumSyncerTypes`): `felix`, `bgp`, `tunnel-ip-allocation`, and
`node-status`. Each pipeline turns a stream of datastore updates into a
cached, fan-out-able snapshot:

```
Source → DedupeBuffer → (SendToSinkForever pump) →
    ValidationFilter (+NodeCounter for felix) →
    ValidatorToCache decoupler → snapcache.Cache → syncserver.Server
```

- **Source** produces syncer callbacks (`OnStatusUpdated`, `OnUpdates`).
  Historically this was always a real datastore `bapi.Syncer`; it is now
  abstracted behind the [`SyncerSource`](#syncersource-abstraction) interface
  so it can also be a connection to an upstream Typha (see
  [Hierarchical mode](#hierarchical-chained-mode)).
- **DedupeBuffer** (`libcalico-go/lib/backend/syncersv1/dedupebuffer`) is the
  permanent head of the pipeline. It is an in-order, per-key de-duplicating
  queue: if an update arrives for a key already on the queue, the queued value
  is replaced rather than appended. This bounds in-flight memory to the size of
  the datastore even under overload, and it is also where reconciliation
  happens (see the [stable-element invariant](#the-dedupe-buffer-is-the-stable-element-binding-invariant)).
  Its `SendToSinkForever` goroutine pumps batches downstream.
- **ValidationFilter** (`typha/pkg/calc`) re-validates each KV (defence in
  depth — bad data should never reach clients). For the felix pipeline a
  **NodeCounter** is inserted here; it feeds the connection-rebalancing math in
  `typha/pkg/k8s/rebalance.go`.
- **snapcache.Cache** (`typha/pkg/snapcache`) stores a copy-on-write B-tree of
  `syncproto.SerializedUpdate` plus a linked list of **breadcrumbs**. Each
  breadcrumb is a point-in-time snapshot plus the delta that produced it; a
  client follows the breadcrumb chain to receive a consistent snapshot followed
  by a live delta stream. Readiness is reported as
  `Ready: pendingStatus == InSync`.
- **syncserver.Server** (`typha/pkg/syncserver`) accepts client connections and
  serves each the breadcrumb chain for its requested syncer type.

Orientation files: `pkg/daemon/daemon.go` (`addSyncerPipeline`,
`CreateServer`, `Start`), `pkg/snapcache/cache.go`,
`pkg/syncserver/sync_server.go`, `pkg/syncclient/sync_client.go`.

### The Felix/Typha protocol

The wire protocol is defined and documented in the package doc comment of
`pkg/syncproto/sync_proto.go` — **read that comment before touching the
protocol.** Key points that constrain all future changes:

- Messages are gob-encoded, wrapped in an `Envelope`. KV pairs are carried as
  `SerializedUpdate` (key/value pre-serialized to the libcalico-go "default"
  encoding) so each KV is serialized once and fanned out to all clients.
- The handshake is `MsgClientHello` → `MsgServerHello`. After it, Typha streams
  `MsgKVs`, `MsgSyncStatus`, and `MsgPing`; the client replies to pings with
  `MsgPong`.
- **Protocol-upgrade rule (binding):** never send a new message _type_ to a
  peer that has not advertised support for it. Support is advertised with
  `Supports*` booleans in the hello messages; gob defaults unknown fields to
  zero, so an old peer reads `false` and you must not send the new message.
  Mid-stream protocol switches (as used for snappy compression via
  `MsgDecoderRestart`) must drain the old-format data and wait for an ACK
  before sending new-format data.

### Syncer API contract

Sources and the pipeline obey the `bapi.Syncer` / `bapi.SyncerCallbacks`
contract (`libcalico-go/lib/backend/api`):

- Updates are **eventually consistent**: the consumer converges on the
  datastore state but may see reordering between keys and may "skip ahead" past
  intermediate states (which is exactly what the DedupeBuffer exploits).
- Status transitions are `WaitForDatastore → ResyncInProgress → InSync`.
  `WaitForDatastore` is the zero value of `api.SyncStatus`. `InSync` means "you
  have seen a complete snapshot"; it gates snapcache readiness.
- A source that delivers a fresh full snapshot (e.g. after a reconnect) signals
  it by calling `OnTyphaConnectionRestarted()` on a restart-aware sink before
  re-delivering, then `InSync` when the snapshot is complete.

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

## Hierarchical (chained) mode

At very high scale the datastore (the API server) becomes the fan-out
bottleneck: every Typha places its own watch. Hierarchical mode removes that
bottleneck by letting a Typha source its data from **another Typha** instead of
the datastore, so Typhas can be arranged in a tree (leader → followers, and
ultimately leader → tier-1 → tier-2). This is the WS-A foundation; dynamic role
selection via leader election (above) is wired in by WS-C. See
`plans/hierarchical-typha/`.

Hierarchical mode is gated entirely behind `TYPHA_HIERARCHYENABLED` (default
**off**). With it off, Typha's behaviour and wire output are unchanged from the
non-hierarchical design above.

### `SyncerSource` abstraction

Each pipeline's head can be fed by either kind of source, behind one interface
(`typha/pkg/syncsource`):

```go
type SyncerSource interface {
    Start(ctx context.Context) error
    Stop()                 // idempotent; blocks until no more callbacks can fire
    Done() <-chan struct{} // closed on fatal error or Stop
}
```

- **`datastoreSource`** wraps a real `bapi.Syncer`. The syncer is constructed
  eagerly (matching the historical timing where the syncer object existed from
  server-setup time) and started on `Start`. `Stop` delegates to
  `bapi.Syncer.Stop()`, which already blocks until the syncer's run loop has
  exited.
- **`upstreamTyphaSource`** wraps a `syncclient.SyncerClient` connected to an
  upstream Typha, with `SyncerType` set per pipeline. It runs a
  retry-with-backoff loop for the _initial_ connection (so startup tolerates the
  upstream not being ready); once connected, the syncclient handles its own
  reconnections because its callbacks (the DedupeBuffer) are restart-aware.

**Stop contract (binding):** `Stop()` must not return until no further
callbacks can be delivered to the sink. WS-C relies on this: after `Stop()`
returns it is safe to attach a new source to the same buffer and call
`OnTyphaConnectionRestarted()` without racing callbacks from the old source.
`syncclient.SyncerClient` provides this via its own `Stop()`, which cancels the
connection context and waits on the `Finished` WaitGroup (the main loop, and
hence all callbacks, has returned by then).

### One connection per syncer type

A follower Typha runs up to `syncproto.NumSyncerTypes` (4) syncclient
connections to its upstream — one per pipeline, mirroring how Felix/confd
connect today. The pipelines are independent; there is no cross-pipeline
coordination.

### The dedupe buffer is the stable element (binding invariant)

The DedupeBuffer is created once at daemon startup and lives for the whole
process. **Sources are swapped behind it; it never moves.** All reconciliation
flows through it:

- On a source reconnect (or, in WS-C, a source swap on promotion/demotion), the
  new source calls `OnTyphaConnectionRestarted()`. The buffer snapshots its
  current live-key set, then, as the new snapshot streams in, marks keys as
  seen. At the following `InSync` it synthesizes deletions for any live key not
  seen during the resync (`onInSyncAfterReconnection`). Downstream
  (validator → snapcache) never learns that a swap happened.
- Because the buffer is downstream of the source and upstream of the cache,
  clients of this Typha keep being served the last-known-good cache throughout
  a source transition.

This is why hierarchical mode needs **no new reconciliation code**: the existing
DedupeBuffer machinery, already used by Felix on Typha reconnect, does the work.
Do not change DedupeBuffer semantics — Felix and confd depend on it; extend via
new methods if something is genuinely missing.

A consequence the cache must tolerate: the buffer can forward a deletion for a
key the downstream snapshot cache does not hold (a delete-of-absent-key, e.g. a
synthesized delete). `snapcache` deletes by key, so this is a no-op for stored
state while still recording the delete in the breadcrumb delta (Felix needs the
delete event for its stats). See
`dedupebuffer/dedupe_buffer_absent_delete_test.go`.

### Serve stale while reconnecting (binding behaviour)

A follower that loses its upstream keeps serving its current cache (marked
not-in-sync) while it reconnects/re-elects. It does **not** fall back to a
direct datastore connection (that would risk a thundering herd on the API
server — the exact thing hierarchy protects against). Readiness reflects sync
status so orchestration can observe it.

### TLS is symmetric

Typha-as-client reuses the existing `syncclient.Options` TLS fields
(`CertFile`/`KeyFile`/`CAFile`/`ServerCN`/`ServerURISAN`, verified by
`tlsutils.CertificateVerifier`). These are configured via the `TYPHA_CLIENT*` /
`TYPHA_UPSTREAMSERVER*` params. The upstream's existing `ClientCN`/`ClientURISAN`
checks must accept the Typha client certificate.

### Self-connection guard

Even with a statically-configured upstream, a Typha must not chain to itself.
`daemon.go` installs a `discovery.WithPostDiscoveryFilter` that drops any
discovered endpoint resolving to our own pod IP (`POD_IP`) or our hostname's
addresses. This is the minimal guard; WS-C extends it into full cycle
prevention.

### Configuration

All hierarchical params default off/empty so the standard deployment is
byte-for-byte unchanged (`pkg/config/config_params.go`):

| Param (env `TYPHA_<UPPER>`) | Meaning |
|---|---|
| `HierarchyEnabled` | Master gate (bool, default false). |
| `UpstreamAddr` | Static upstream `host:port` (mutually exclusive with the service-discovery params). |
| `UpstreamK8sServiceName` / `UpstreamK8sNamespace` / `UpstreamK8sPortName` | Discover upstream Typhas via EndpointSlices. |
| `ClientKeyFile` / `ClientCertFile` / `ClientCAFile` / `UpstreamServerCN` / `UpstreamServerURISAN` | Client-side TLS for the upstream connection. |
| `UpstreamReadTimeout` / `UpstreamWriteTimeout` | Passed through to `syncclient.Options`. |

Validation (`Config.Validate`): when `HierarchyEnabled` is set, an upstream
must be configured (WS-A has no election to provide one dynamically), and
`UpstreamAddr` and `UpstreamK8sServiceName` are mutually exclusive. The
client-side TLS params follow the same "all-or-nothing (except CN/URISAN)" rule
as the server-side params.

Datastore client note: even in hierarchical mode Typha still creates its
datastore client for config loading / `EnsureInitialized` and for the
connection-rebalance K8s polling. Those are cheap calls to the API server; only
the heavy watch-everything syncers move to the upstream.

## Review notes

When reviewing or writing a PR that touches Typha:

- **Protocol changes** must obey the upgrade rule in `sync_proto.go`
  (hello-flag negotiation; no unnegotiated message types; drain-then-switch for
  mid-stream format changes). Old Felix ↔ new Typha and new Felix ↔ old Typha
  must both keep working.
- **Pipeline changes** must keep the DedupeBuffer as the permanent head and keep
  all reconciliation flowing through it. Do not stack a second decoupler in
  front of the buffer — its `SendToSinkForever` pump already provides async
  decoupling. Do not move or recreate the buffer when swapping sources.
- **`SyncerSource.Stop()`** implementations must block until no more callbacks
  can fire. A source that returns from `Stop()` while a callback is still in
  flight is a bug that will corrupt the next source's snapshot.
- **Hierarchy must stay opt-in.** With `HierarchyEnabled=false` there must be no
  behavioural or wire-format difference and no new goroutine leaks (the fv-tests
  have leak checks). New config must default off/empty.
- **`gob` round-trip fidelity.** A chained Typha deserializes → validates →
  re-serializes each KV. Watch `Revision any` (string vs struct) round-tripping
  through the extra hop; there is prior art in the `syncproto` tests.
- **Don't change DedupeBuffer semantics** (it is in `libcalico-go` and shared
  with Felix/confd). Extend with new methods and run the felix daemon-adjacent
  UTs if you must touch it.
- **Tests ship in the same PR.** New behaviour needs a UT at the lowest
  meaningful level; the chained data path is covered by the `typha/fv-tests`
  chain tests (parity across all four syncer types, upstream-restart
  reconciliation, compression across the chain).
