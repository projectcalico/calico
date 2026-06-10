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
a singleton). The two-tier slot acquirer (`pkg/slotacquirer`, see "Two-tier
fan-out") relies on this to run an independent elector per slot — the leader
Lease plus N tier-1 Leases — each with its own Lease object.

### RBAC

Leader election and hierarchical-mode self-labelling are namespaced concerns
(the Lease and the Typha pods live in the Typha namespace), so the permissions
live in a **namespaced `Role` + `RoleBinding`** (`calico-typha-leader-election`,
in the Typha namespace), bound to the `calico-node` ServiceAccount that Typha
runs as — **not** on the cluster-wide `calico-node` ClusterRole. Putting these
on the ClusterRole would grant every calico-node pod cluster-wide the right to
create Leases and (worse) patch pods anywhere; the namespaced Role limits the
blast radius to the Typha namespace.

The Role grants:

- `coordination.k8s.io/leases: create` — unrestricted within the namespace
  (Kubernetes cannot scope `create` to `resourceNames`)
- `coordination.k8s.io/leases: get, update` — scoped via `resourceNames` to
  `calico-typha-leader` plus, in two-tier mode, the tier-1 lease names
  `calico-typha-tier1-0..N-1` (the chart `range`s over `tier1Count` to emit
  them). The scoping is preserved as tier-1 names are added — it is **not**
  widened to all leases and **not** moved back to the shared ClusterRole.
- `pods: patch` — for a Typha self-labelling its own pod's tier. Kubernetes RBAC
  has no self-reference, so `patch` cannot be restricted to the pod's own name;
  namespace scoping is the available blast-radius limit. (Not broadened for the
  tier label — same self-patch-own-pod pattern as WS-C.)

The Role/RoleBinding are values-gated on `typha.hierarchy.enabled` (matching
where the chart sets `TYPHA_LEADERELECTIONENABLED`), so a non-hierarchical
deployment's RBAC is unchanged. If `LeaseName` is customised, the
`resourceNames` restriction must be updated accordingly.

**Trade-off (OSS chart):** the open-source chart shares one ServiceAccount
(`calico-node`) between calico-node and Typha, so namespace scoping is the
tightest available limit without introducing a dedicated Typha ServiceAccount
(out of scope here). The operator deployment already gives Typha a dedicated SA;
WS-G handles that side, where the grant can be SA-scoped as well.

### Health and metrics

- Health reporter `"LeaderElection"` is registered on the `HealthAggregator`
  while the elector loop is running. Liveness only — readiness is not gated on
  holding the lease (a follower Typha is fully ready to serve cached data).
- `typha_leader` gauge: 1 when this instance holds the lease, 0 otherwise.
- `typha_leader_transitions_total` counter: increments on every
  Leader→Follower or Follower→Leader transition.
- `typha_leader_holder_info` gauge vec (label `holder`): info-style gauge,
  value always 1, label carries the current holder's pod-name identity.

Two-tier metrics (`pkg/slotacquirer`):

- `typha_hierarchy_role` gauge vec (label `role`): per-role gauge, exactly one
  of `{leader,tier1,tier2}` is 1 at any time.
- `typha_hierarchy_held_slot` gauge vec (label `slot`): info-style gauge, value
  always 1, label carries the held slot/Lease name (`none` when holding
  nothing) — doubles as the upstream-identity signal.

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
| `RoleTransitionDebounce` | How long the desired role must be stable before the role manager acts (default 2s). |
| `LeaderServiceName` / `LeaderServicePortName` | Headless Service that selects the leader pod; followers discover their upstream through it (defaults `calico-typha-leader` / `calico-typha`). |

Validation (`Config.Validate`): when `HierarchyEnabled` is set, either a static
upstream must be configured **or** leader election must be enabled (so the role
manager can discover the leader dynamically — see "Role state machine" below).
`UpstreamAddr` and `UpstreamK8sServiceName` are mutually exclusive. When relying
on election (no static upstream) the datastore must be `kubernetes` and `PodName`
must be set (downward API). The client-side TLS params follow the same
"all-or-nothing (except CN/URISAN)" rule as the server-side params.

Datastore client note: even in hierarchical mode Typha still creates its
datastore client for config loading / `EnsureInitialized` and for the
connection-rebalance K8s polling. Those are cheap calls to the API server; only
the heavy watch-everything syncers move to the upstream.

## Role state machine (promotion/demotion)

WS-A made the pipeline source swappable; WS-B added leader election. WS-C wired
them together so a hierarchy-enabled deployment self-organises; WS-E generalised
the two-state machine to three roles for two-tier fan-out (see "Two-tier
fan-out" below). The elected leader runs real datastore syncers, every other
Typha follows (a tier-1 from the leader, a tier-2 from a tier-1 or — in
single-tier mode — directly from the leader), and promotion/demotion happen
**in-process** with no restart. The role manager lives in `pkg/rolemanager` and
runs as a single goroutine per Typha process, constructed and started from
`daemon.go` (`startSlotAcquirerAndRoleManager`) only when hierarchy + election
are enabled and no static upstream is configured (`roleManaged` mode). A static
upstream pins the Typha as a follower and bypasses the role manager (manual
chaining / tests).

The role manager consumes role transitions from the **slot acquirer**
(`pkg/slotacquirer`, see "Two-tier fan-out"), which publishes one of three
roles: `Leader`, `Tier1`, `Tier2`. In single-tier mode (`Tier1Count == 0`) the
acquirer only ever publishes `Leader`/`Tier2`, reproducing the WS-C two-state
machine exactly.

### States and transition procedure

```
             ┌──────────┐        ┌──────────┐        ┌──────────┐
   start ───→│  TIER2   │───────→│  TIER1   │───────→│  LEADER  │
             │(src=t1   │←───────│(src=     │←───────│(real     │
             │ service) │        │ leader)  │        │ syncers) │
             └──────────┘        └──────────┘        └──────────┘
   (promotion ladder shown; any role may transition directly to any other)
```

The role manager picks the source for the target role via a single per-pipeline
`NewSourceForRole(role)` factory: `Leader` → datastore syncer; `Tier1` →
upstream syncclient to the leader Service; `Tier2` → upstream syncclient to the
tier-1 Service (or, in single-tier mode, the leader Service — the daemon aliases
the two discoverers there).

The initial state is **SOURCELESS** (no source started yet) so the first
transition's "stop old source" step is a no-op on cold start. On startup the
manager converges immediately to TIER2 (a cold cluster has no leader, so
everyone is a leaf until the slots are filled); from then on it follows the
acquirer.

For each of the four pipelines the swap is identical in both directions and runs
concurrently across pipelines, but the role manager is strictly serial per role
change (a single goroutine; only one transition in flight at a time):

1. `oldSource.Stop()` — blocks until no more callbacks can be delivered into the
   dedupe buffer (the `SyncerSource.Stop` contract). This ordering is what makes
   the swap race-free: step 2 cannot observe a late callback from the old source.
2. `dedupeBuffer.OnTyphaConnectionRestarted()` — the buffer snapshots its
   live-key set and discards queued in-flight updates.
3. `newSource.Start(ctx)` — the fresh source delivers `WaitForDatastore →
   ResyncInProgress → snapshot → InSync`; at `InSync` the buffer synthesizes
   deletes for keys that vanished while we were switching. Downstream
   (validator → snapcache → connected clients) sees an ordinary resync, exactly
   as a Felix riding a Typha restart does today. This is why the dedupe buffer is
   the stable element (see the binding invariant above): no swap-specific
   reconciliation code exists.

### Debounce, flap protection, serialization

Role changes are debounced (`RoleTransitionDebounce`, default 2s): the desired
role must be stable for the debounce period before a transition starts. A
transition already in flight is never interrupted — the manager finishes it,
then re-evaluates the latest desired role. The elector's `Roles()` channel is
treated as level state (it drops the oldest value on overflow), so the manager
always converges to the most recently received role. A 100ms×10s flap storm
converges to the final role with no source overlap and no goroutine leak
(covered by `rolemanager` UTs under the race detector).

### Tier advertisement, discovery and self/cycle prevention

Every Typha advertises its tier by labelling its **own pod** with
`projectcalico.org/typha-tier` (via `pkg/k8s.PodLabeller`, a strategic-merge
patch on the pod that touches only that one key). The pod template sets `"2"`;
on acquiring the leader / a tier-1 slot the role manager patches the value to
`"leader"` / `"1"`, and back to `"2"` on demotion. Per-tier headless Services
select on this label:

- `calico-typha-leader` selects `typha-tier=leader`.
- `calico-typha-tier1` selects `typha-tier=1`.

Tier-1 Typhas discover the leader through `calico-typha-leader`; tier-2 Typhas
discover their upstream through `calico-typha-tier1` (or, in single-tier mode,
through `calico-typha-leader`). Inter-Typha upstream discovery uses plain
shuffled ordering — no same-node preference between Typha tiers (anti-affinity
already spreads them). The main `calico-typha` Service is unchanged and still
selects all Typhas (Felix can connect to any ready one; who-may-connect is
policed client-side — see "Two-tier fan-out").

**Label ordering (decision):** on **promotion** the pod's tier label is applied
*after* the role manager has started the new sources (step 3 above); on
**demotion** the (lower) label is applied *before* the swap so clients/Typhas
stop being directed at us at the old tier as early as possible. Final "don't
direct anyone at a not-yet-synced upstream" gating is provided by pod
**readiness**: the snapcache health reporters set `Ready` only when the syncer is
`InSync`, the pod's readiness probe reflects that, and an unready pod is removed
from the Service's EndpointSlice. We chose readiness-gating (rather than blocking
the label until InSync inside the role manager) because it reuses the existing
health plumbing and degrades correctly if the upstream later falls out of sync.

Cycle/self-connection prevention (`daemon.filterOutSelf`, installed as a
post-discovery filter): we drop any discovered endpoint that resolves to our own
pod IP. The per-tier Service selectors are the primary guard against connecting
to the wrong tier; a stale label lingering after a SIGKILL is bounded because the
dead pod's endpoints are reaped from the Service's EndpointSlice.

### Readiness across transitions

The snapcache is the stable element and keeps running across a source swap, so
its health reporter is never deregistered. During a swap the dedupe buffer sends
`ResyncInProgress` (cache → not Ready) then `InSync` (cache → Ready); because the
cache goroutine keeps reporting on its own health ticks, the reporter's timeout
never expires mid-transition. A follower is Ready only when all four caches are
InSync — correct during bootstrap (followers are not Ready until they have
synced from the leader).

### Dual-leadership window

Leader election is best-effort (see "Leader election" above): clock skew can let
two Typhas both believe they lead for up to `LeaseDuration`. This is safe — both
run real datastore syncers and serve identical correct data; the only cost is
transient extra datastore load and both pods carrying the leader label briefly.
The loser demotes when it observes leadership loss. Nothing in the swap procedure
corrupts state under dual leadership: each Typha independently reconciles its own
buffer.

### Graceful shutdown ordering

On SIGTERM the daemon releases any held lease (`acquirerCancel()` →
`ReleaseOnCancel`) **before** starting the server's connection drain, so another
Typha can win the slot and stand up its sources early, shortening the window in
which clients have no fresh upstream. The role manager stops all sources when its
context is cancelled.

### Bootstrap and misconfiguration

Cold start: all Typhas come up TIER2 with no leader → the slot acquirer fills the
leader (and any tier-1) slots → the winner promotes (SOURCELESS→LEADER, so "stop
old source" is a no-op) → labels its pod → other Typhas discover their upstream
and sync. Until then leaf Typhas are not Ready, which is correct. Hierarchy
enabled with election but a non-Kubernetes datastore, or without `PodName`, is a
fatal config error at startup; `Tier1Count>0` alongside a static upstream is also
rejected.

## Two-tier fan-out

For the very largest clusters (target 1M nodes) a single leader cannot fan out
to every Typha. Two-tier mode (`Tier1Count = N > 0`) inserts a small elected set
of **tier-1** Typhas between the leader and the leaf **tier-2** Typhas:

```
            datastore (kube-apiserver)
                      │ (watch, ×1)
                  [ leader ]            ← Lease: calico-typha-leader
                ┌────┼────┐
            [t1-0] [t1-1] … [t1-(N-1)]  ← Leases: calico-typha-tier1-0..N-1
           ╱   │  ╲   ...   ╱  │ ╲
        [tier-2 × hundreds/thousands]   ← everyone else (no slot)
        ╱│╲      ...        ╱│╲
     felix/confd clients (×1M)
```

`Tier1Count = 0` collapses this to the single-tier (WS-C) topology exactly:
tier-2 Typhas connect straight to the leader and no tier-1 Leases exist.

### Slot election with lazy candidacy (`pkg/slotacquirer`)

client-go leader election is single-leader-per-Lease, so we run **one Lease per
slot**: `calico-typha-leader` plus `calico-typha-tier1-0..N-1`. Every Typha runs
one `slotacquirer.Acquirer`, which makes the instance hold **at most one** slot
and converges the deployment so **exactly one** instance holds each slot. The
role follows from the held slot: leader slot → `Leader`; a tier-1 slot →
`Tier1`; nothing → `Tier2`.

The naive approach — one always-running client-go elector per Lease on every
Typha — would have every idle leaf Typha polling every Lease every `RetryPeriod`
forever: roughly `P × (N+1) / RetryPeriod` lease GETs/s against the API server in
steady state, even when all slots are filled and nobody can win anything. At the
1M-node scale (thousands of tier-2 Typhas) that is a self-inflicted DoS on the
exact component the hierarchy exists to protect.

**Lazy candidacy** fixes this and is the one piece of nonstandard election code
(isolated in `slotacquirer` and UT-ed hard, including by counting API calls):

- A Typha that holds no slot does **not** keep electors running. It runs a single
  cheap watch loop that **lists** the Leases every `SlotWatchInterval`
  (default 10s) and only starts a real per-slot `leaderelection.Elector` for a
  slot that looks *acquirable* (no holder, empty holder, held by us, or the
  holder's lease has expired: `renewTime + leaseDuration < now`).
- The instant it wins any slot it cancels every other campaign elector (each runs
  on its own child context) — this is what enforces "≤1 slot per candidate",
  releasing any other slot momentarily grabbed during the dual-acquisition
  window — and keeps the winner's elector running to renew the lease.
- When it loses its held slot it returns to the watch loop.

Steady-state cost per idle Typha is therefore one LIST every `SlotWatchInterval`
instead of `(N+1)` renew-GETs every `RetryPeriod` — campaign traffic only appears
transiently when a slot actually frees up. (Alternative considered and rejected:
the leader appoints tier-1 by writing a ConfigMap — simpler API-load profile but
invents a bespoke coordination protocol and a single point of appointment.)

Any Typha may win the leader lease, **including a tier-2** — the role manager
handles a direct `Tier2 → Leader` jump, not just the ladder step (fv-tested).

### Client (Felix) connection preference

Decision (Shaun): who-may-connect-to-the-leader is policed **client-side**, not
by Service membership. The main `calico-typha` Service keeps selecting **all**
Typhas. Felix's discovery (`pkg/discovery`, enabled via `WithTierServices`)
additionally lists the leader and tier-1 Services' endpoints and cross-references
them against the main Service to classify each endpoint's tier (EndpointSlices
don't expose pod labels, so the per-tier Services are the tier-information
channel). The policy:

1. A client on the **same node** as a Typha always prefers that Typha — whatever
   its tier, including the leader. Smooths bootstrap; the node's local Typha is
   always usable.
2. When **tiering is active**, an **off-node** client may use **only** tier-2
   Typhas; the leader and tier-1 are filtered out for off-node clients.
3. "Tiering active" is detected client-side as "the tier-1 Service has ≥1
   endpoint" — no need to plumb `Tier1Count` to Felix. When not active
   (single-tier / small clusters), off-node clients may use any Typha.
4. Endpoints of **unknown** tier (label/Service lag, or a brand-new cluster with
   no labels yet) count as tier-2 to **fail open** — clients can always connect.

Ordering: same-node endpoints first (any tier), then — if tiering active — only
tier-2 endpoints, shuffled. No new Felix config: the preference is automatic
(rides the shared discovery package).

### Promotion drain

On promotion **out of** tier-2 (to tier-1 or leader) this Typha should no longer
serve off-node leaf clients. The role manager calls
`server.DrainOffNodeClients()` after the source swap: it drops every client
connection whose hello `Hostname` differs from this Typha's `NodeName`, **without**
shutting the server down. Dropped clients re-discover and land on a tier-2 Typha;
a same-node client (which always prefers its local Typha) is kept and just
re-syncs through its dedupe buffer. Same-node-ness is matched on the client's
hello hostname (Felix's node name).

### Rebalancing / connection-limit math (`pkg/k8s.CalculateMaxConnLimitForTier`)

The per-Typha connection limit is computed per serving tier:

- **tier-2** serves leaf clients: `expected ≈ nodes × syncerTypes ÷ #tier2`.
- **tier-1** serves tier-2 Typhas: `expected ≈ #tier2 × syncerTypes ÷ #tier1`.
- **leader** serves tier-1 Typhas: `expected ≈ #tier1 × syncerTypes` (single
  instance, so it must accept them all — gets the upper limit).

Each divides by `(peers − 1)` for rolling-upgrade slack and adds 20% headroom
(the same shape as the original single-tier `CalculateMaxConnLimit`), then clamps
to the configured lower/upper limits. In single-tier mode (`#tier1 == 0`) a
leader serving leaf clients falls back to the original node-based math, so WS-C
behaviour is preserved exactly. Each formula is UT-ed.

### Sizing guidance

1M nodes, ~200 clients/Typha ⇒ ~5,000 tier-2 Typhas ⇒ ~20,000 upstream
connections ÷ tier-1 ⇒ `N = 100` tier-1 at ~200 conns each; the leader serves
~400 (4 syncer types × 100). `Tier1Count` is operator-set for now (auto-scaling
from node count is a follow-up — see WS-G's autoscaler tier math).

### Failure analysis

- **Leader death.** The leader lease expires; the slot acquirer on every Typha
  (including tier-2s) sees the slot become acquirable on its next watch and
  campaigns; one wins and promotes (`Tier2→Leader` or `Tier1→Leader`). Tier-1
  Typhas keep serving their last-known-good cache (marked not-in-sync) while
  reconnecting to the new leader. Worst case recovery ≈ `LeaseDuration` + resync.
- **Tier-1 death.** The tier-1 lease expires; another Typha wins it. Meanwhile
  the affected tier-2 Typhas serve stale (binding decision 5: fail-safe,
  serve-stale) and reconnect to a surviving / replacement tier-1 via the tier-1
  Service. Leaf clients ride through via their dedupe buffers.
- **Partition between tiers.** A tier-2 cut off from all tier-1s serves stale and
  is not-Ready; its clients keep their last cache. No fallback to a direct
  datastore connection (deliberately — that risks the thundering-herd the
  hierarchy prevents; revisit after soak).

## Snapshot integrity checking

With data flowing through multiple Typha hops and through the
promotion/demotion reconciliation path, a corruption bug (e.g. a dedupe-buffer
reconciliation error) could silently drop or duplicate a KV. The integrity
check catches that: the server reports a checksum of its snapshot; the client
compares it against a checksum computed over its own reconstructed state. The
check is **hop-by-hop** — each link (leader↔tier-1, typha↔typha, typha↔felix)
validates independently, which localises faults and avoids requiring identical
byte representations across software versions.

### Checksum definition (`pkg/synccheck`)

Order-independent, incremental checksum over the set of live KVs:

- Per-entry digest: `h(entry) = xxhash64( uint64-LE(len(key)) ‖ key ‖ value )`,
  where `key`/`value` are the wire fields of `SerializedUpdate` (the same bytes
  the client receives). The length prefix makes the key/value boundary
  unambiguous. 64-bit output.
- Store checksum: per-entry digests combined with **XOR**. XOR gives O(1)
  add/remove/clobber, so the cache maintains it incrementally:
  - insert: `xor ^= h(new)`; delete: `xor ^= h(old)`;
  - clobber: `xor ^= h(old); xor ^= h(new)` (old value already in hand in
    `publishBreadcrumb`).
- `KVCount` is tracked alongside: cheap, and it catches gross errors with a
  clearer message than a hash mismatch (and survives re-serialization — see
  version skew).

Hash choice: `github.com/cespare/xxhash/v2` (already in the module graph).
**Both peers must agree on the algorithm forever**; a future change must be
gated behind a new hello flag. The 64-bit width is fine for an integrity (not
security) check — XOR cancellation between two distinct live entries needs a
64-bit collision, and the unique key is part of every digest.

### Server side

`snapcache.Cache` keeps a rolling `synccheck.Checksum`, updated in
`publishBreadcrumb()` next to the existing old-value lookup. Dedupe-skipped
writes (old == new) do **not** touch the checksum; delete-of-absent is a no-op.
Each `Breadcrumb` carries the checksum+count as of that breadcrumb (immutable
after publication, so per-client goroutines read it lock-free). The value bytes
in the B-tree are exactly the bytes sent on both the streaming and the
pre-serialized binary-snapshot paths (`snap_precalc.go` iterates the same
breadcrumb KVs and never mutates `SerializedUpdate.Value`), so the checksum
describes what the client actually receives.

### Protocol carriage

Negotiated via hello flags (`MsgClientHello.SupportsChecksum`,
`MsgServerHello.SupportsChecksum`): the server only emits checksum data to
clients that advertised support, and only echoes `SupportsChecksum: true` when
the client asked. gob's zero-value rule keeps this safe for old peers. New
message `MsgChecksum{Checksum uint64; KVCount int64}` is registered with gob.

The server sends `MsgChecksum` from `sendDeltaUpdatesToClient`:

1. immediately after the `MsgSyncStatus(InSync)` that ends initial sync — the
   stream position makes it unambiguous which state it describes;
2. thereafter, after the deltas of a breadcrumb, at most once per
   `ChecksumInterval` (~30s). The delta loop coalesces breadcrumbs when the
   client lags; only the **last** coalesced breadcrumb's checksum is emitted, so
   it describes the state after everything just sent.

### Client side (typha-as-client)

A follower Typha's own snapcache independently maintains the same rolling
checksum. When `MsgChecksum` arrives, the deltas that produced it are still
flowing through the follower's dedupe buffer → validator → cache, so comparison
is **deferred**: `synccheck.Verifier` records the expectation and a timer
(driven from the syncclient) re-compares against the follower's current
breadcrumb checksum. A mismatch must **persist across N consecutive checks**
(default 3) before it is treated as real — in-flight skew clears within a check
or two, a real divergence is permanent, so persistence filtering eliminates
false positives. (Felix-bound checking is a deliberate follow-up: Felix has no
value-preserving store to checksum; that would add an opt-in per-entry digest
map in the syncclient layer.)

**Version skew:** an intermediate Typha re-serializes values into its own
cache. With identical code versions the bytes are identical (deterministic Go
JSON marshalling); across versions the serialized form can legitimately differ.
The deferred comparison spans the follower's *re-serialized* cache vs the
upstream's checksum, so when `MsgServerHello.Version != ours` the client
downgrades to **KVCount-only** comparison (counts survive re-serialization).

### Mismatch handling

Always: log (both checksums, counts, syncer type) + Prometheus
(`typha_checksum_mismatches_total{syncer}`, `typha_checksum_matches_total`,
`typha_checksum_last_compare_ok` gauge). Remediation is config
`ChecksumMismatchAction` (`log` | `reconnect`, default `reconnect`):
`reconnect` tears the connection down so the existing restart path
(`OnTyphaConnectionRestarted` reconciliation) produces a clean re-sync,
**rate-limited** to ~1 forced reconnect / 10min / pipeline so a persistent
mismatch can't melt the hierarchy. After rate-limiting kicks in we keep serving
(do not go unready); we only alarm.

### Configuration

| Param (env `TYPHA_<UPPER>`) | Meaning |
|---|---|
| `ChecksumEnabled` | Client-side verification on a follower (bool, default true; harmless when not hierarchical — nothing to verify). |
| `ChecksumMismatchAction` | `log` or `reconnect` (default `reconnect`). |
| `ChecksumInterval` | Server's periodic-checksum interval after the initial in-sync checksum (default 30s). |

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
- **Checksum fidelity.** Any change to how a KV is stored or sent must keep the
  B-tree value bytes equal to the wire bytes on *both* send paths (streaming and
  binary snapshot), or the integrity check will false-positive. The checksum
  algorithm and per-entry digest in `pkg/synccheck` are a wire contract: both
  peers compute them independently, so a change needs a hello-flag-gated version
  bump and updated golden vectors. Maintain the checksum only on real state
  changes (not dedupe-skipped writes or delete-of-absent).
- **Tests ship in the same PR.** New behaviour needs a UT at the lowest
  meaningful level; the chained data path is covered by the `typha/fv-tests`
  chain tests (parity across all four syncer types, upstream-restart
  reconciliation, compression across the chain) and the checksum tests
  (clean-run matches with zero false positives, fault-injection detection +
  reconnect remediation, back-compat with non-checksum clients, version-skew
  count-only).
