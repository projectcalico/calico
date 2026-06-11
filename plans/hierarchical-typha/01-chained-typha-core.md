# WS-A: Chained Typha core (Typha as a client of another Typha)

## Goal

Make Typha able to source each of its syncer pipelines from an **upstream
Typha** (via `syncclient`) instead of a real datastore syncer, selected by
static configuration. Deliverable: with `TYPHA_HIERARCHYENABLED=true` and
`TYPHA_UPSTREAMADDR=<host:port>` (or upstream service discovery config), a
Typha serves exactly the same data to its clients as the upstream does, with
full reconciliation on upstream reconnection. No leader election — this is the
data-path foundation that WS-C later drives dynamically.

Also in scope: create `typha/DESIGN.md` documenting Typha's existing
architecture plus the new chained mode (the repo requires a design doc and
Typha has none).

## Required reading

- `plans/hierarchical-typha/00-overview.md` (esp. binding decisions 1, 3, 4, 6)
- `typha/pkg/syncproto/sync_proto.go` package doc comment (protocol + upgrade rules)
- `typha/pkg/daemon/daemon.go` — `addSyncerPipeline()` (~line 263),
  `CreateServer()` (~305), `Start()` (~352 area)
- `typha/pkg/syncclient/sync_client.go` — `New()`, `Start(ctx)`,
  `RestartAwareCallbacks` (~175), `Options` (TLS fields)
- `libcalico-go/lib/backend/syncersv1/dedupebuffer/dedupe_buffer.go` — whole
  file (~400 lines); note `OnTyphaConnectionRestarted()` (76),
  `OnStatusUpdated()` (95), `SendToSinkForever()` (221), `Stop()` (229),
  `onInSyncAfterReconnection()` (344)
- `typha/pkg/syncclientutils/startsyncerclient.go` — canonical
  syncclient+dedupebuffer wiring to copy from
- `felix/daemon/daemon.go:522-587` — how Felix wires discovery, syncclient,
  dedupe buffer, and handles connection failure
- `typha/pkg/config/config_params.go` — config struct-tag pattern (~87-159 and
  ~353-422)

## Current state

Pipeline today (`addSyncerPipeline`):

```
real Syncer → SyncerCallbacksDecoupler → ValidationFilter (+NodeCounter for felix) → Decoupler → snapcache.Cache
```

There is **no dedupe buffer** on Typha's input today, and `bapi.Syncer` has no
notion of "connection restarted" — the real syncer is started once and never
replaced. The syncclient, by contrast, requires its callbacks to implement
`RestartAwareCallbacks` or it dies on disconnect.

## Design

### 1. Introduce a `syncerSource` abstraction per pipeline

Define (in `typha/pkg/daemon` or a new small package, e.g.
`typha/pkg/syncsource`) an interface that both source kinds satisfy:

```go
// SyncerSource produces syncer callbacks into the given sink. Stop must
// fully halt delivery before returning (or before signalling done).
type SyncerSource interface {
    Start(ctx context.Context) error
    Stop()                       // idempotent; blocks until no more callbacks will fire
    Done() <-chan struct{}       // closed when the source has terminated (fatal error or Stop)
}
```

Implementations:

- `datastoreSource`: wraps the existing `newSyncer(callbacks)` +
  `Syncer.Start()/Stop()`. (`bapi.Syncer` already has `Stop()`.)
- `upstreamTyphaSource`: wraps `syncclient.New(discoverer, ...)` with
  `SyncerType` set per pipeline and the pipeline's dedupe buffer as callbacks.
  Verify `SyncerClient` supports clean in-process stop (it is context-driven —
  `Start(ctx)` + `Finished` WaitGroup); if there's no exported Stop, add one
  (cancel the context it captured, wait on `Finished`). **Task: check and, if
  needed, extend syncclient with an explicit `Stop()`; FV reconnection tests
  must still pass.**

`Done()` matters: when an upstream source dies permanently (e.g. exhausted
discovery attempts), the daemon must notice and restart the source — mirror
Felix's pattern of watching `typhaConnection.Finished` (felix/daemon/daemon.go:580).
For WS-A a simple retry-forever loop with backoff inside `upstreamTyphaSource`
is acceptable; WS-C replaces this with the role state machine.

### 2. Put a dedupe buffer at the head of every pipeline

Change `addSyncerPipeline` so the chain becomes:

```
SyncerSource → DedupeBuffer → (SendToSinkForever goroutine) → ValidationFilter (+NodeCounter) → Decoupler → snapcache.Cache
```

- The DedupeBuffer replaces the first `SyncerCallbacksDecoupler` (it is itself
  a decoupling queue — don't stack both; the buffer's `SendToSinkForever`
  pump provides the same async decoupling).
- The buffer is created once at daemon startup and lives for the process
  lifetime; sources attach to it. This is binding decision 1: all
  reconciliation flows through it, for upstream reconnects now and for
  promotion/demotion in WS-C.
- The syncclient calls `OnTyphaConnectionRestarted()` itself on reconnect
  (sync_client.go ~204) since DedupeBuffer implements `RestartAwareCallbacks`.
  Nothing else needed for the reconnect case.
- Check `calc.ValidationFilter` and `snapcache.Cache` tolerate the synthesized
  deletion updates (`UpdateTypeKVDeleted`, nil value) for keys the cache may
  or may not still hold — snapcache treats deletes by key so this should be a
  no-op risk, but add a UT proving delete-for-absent-key is harmless.

Behavioural check for the **datastore-mode regression risk**: with
`TYPHA_HIERARCHYENABLED=false` the only change is the dedupe buffer in the
path. It must be a pure pass-through in steady state (it is: updates queue and
drain). Confirm no measurable added latency in the existing fv-tests benchmarks
and that status transitions (`WaitForDatastore → ResyncInProgress → InSync`)
still propagate to the snapcache exactly as before (snapcache readiness
reporting depends on it — `snapcache/cache.go` reports
`Ready: pendingStatus == InSync`).

### 3. Configuration

New params in `typha/pkg/config/config_params.go` (follow existing tag
pattern; all default-off/empty):

| Param (env `TYPHA_<UPPER>`) | Type | Meaning |
|---|---|---|
| `HierarchyEnabled` | bool, default false | Master gate. |
| `UpstreamAddr` | string | Static upstream `host:port` override (mutually exclusive with service discovery params; mirrors Felix's `TyphaAddr`). |
| `UpstreamK8sServiceName` / `UpstreamK8sNamespace` / `UpstreamK8sPortName` | string | Discover upstream Typhas via EndpointSlices (reuse `typha/pkg/discovery`). For WS-A this can point at a manually-labelled service; WS-C/WS-E define the real per-tier services. |
| `ClientKeyFile` / `ClientCertFile` / `ClientCAFile` / `UpstreamServerCN` / `UpstreamServerURISAN` | string | TLS for the client side of typha (binding decision 4). |
| `UpstreamReadTimeout` / `UpstreamWriteTimeout` | duration | Pass through to `syncclient.Options` (defaults: same as Felix's typha timeouts). |

Validation: if `HierarchyEnabled` and no upstream configured → fatal at
startup (in WS-A; WS-C relaxes this to "wait for election result").

In WS-A, when hierarchy mode is on with a static upstream, the daemon simply
constructs `upstreamTyphaSource`s instead of `datastoreSource`s for all four
pipelines. Note Typha must still create its datastore client for
config loading / node counting? — check `daemon.go` `InitializeDatastore` path
and `k8s.RealK8sAPI` use for rebalancing; keep those working (they talk to the
API server with cheap calls, which is acceptable; only the heavy
watch-everything syncers move to the upstream).

### 4. Self-connection guard (minimal)

Even in static mode, refuse to connect to ourselves: compare resolved upstream
address against our own listen addr/pod IP and skip such endpoints via
`discovery.WithPostDiscoveryFilter`. (WS-C extends this into full cycle
prevention.) Log clearly when filtered.

### 5. `typha/DESIGN.md`

Create it. Contents: current architecture (syncer pipelines, snapcache
breadcrumbs — crib from the Google doc's Background section and
`sync_proto.go`), the syncer API contract (eventual consistency, in-sync
semantics), protocol-upgrade rules pointer, and a new "Hierarchical mode"
section covering the source abstraction, the dedupe-buffer-as-stable-element
invariant, and the serve-stale-while-reconnecting behaviour. Include review
notes per the repo's DESIGN.md conventions (see `felix/DESIGN.md` for shape).

## Tasks (suggested order)

1. Read required reading; re-verify line refs.
2. Add `Stop()`/clean-shutdown support to `syncclient.SyncerClient` if absent;
   UT for stop-during-each-phase (connecting, handshaking, streaming).
3. Introduce `SyncerSource` + `datastoreSource`; refactor
   `addSyncerPipeline`/`Start` to use it. Pure refactor, no behaviour change;
   existing UT + fv-tests green.
4. Insert DedupeBuffer at pipeline head (replacing first decoupler). UT for
   pass-through status propagation; UT for delete-of-absent-key.
5. Add config params + validation + UT.
6. Implement `upstreamTyphaSource` (discovery, TLS, retry/backoff loop,
   per-syncer-type connections).
7. Wire daemon: hierarchy mode selects source type per pipeline.
8. fv-tests: chained harness (see test matrix).
9. Write `typha/DESIGN.md`; chart: no changes needed in WS-A (params are
   env-driven; chart wiring lands with WS-C when the feature is usable).

## Test matrix (same PR)

- **UT**: source abstraction lifecycle; dedupe-buffer-in-pipeline status and
  reconciliation behaviour (use `dedupe_buffer_test.go` mainline test as the
  model: pre-populate, "reconnect", new snapshot missing a key → downstream
  cache sees the delete).
- **typha fv-tests**: extend `ServerHarness` (`typha/fv-tests/server_harness_test.go`)
  to support chaining: harness A (upstream, fed by test decoupler) ← typha
  client pipeline of harness B ← test client. Assert:
  - Full snapshot parity between A's cache and B's cache and a client of B
    (keys + values + in-sync status), for all four syncer types.
  - Kill/restart A's server: B serves stale data meanwhile, reconciles after
    reconnect (adds, updates, and deletes that happened during the outage all
    reach B's client). This is the single most important test in WS-A.
  - Compression and decoder-restart work across the chain (B as client
    negotiates snappy with A).
- **Regression**: full existing `typha` UT + fv-tests pass with hierarchy off.

## Acceptance criteria

- Hierarchy off → no behavioural diff (existing suites green, no new goroutine
  leaks: fv-tests have leak checks).
- Hierarchy on + static upstream → byte-identical cache content vs upstream,
  surviving upstream restarts with correct reconciliation.
- `typha/DESIGN.md` exists and documents the above.

## Out of scope

Leader election (WS-B), dynamic role switching (WS-C), checksums (WS-D),
tier preferences (WS-E), chart/manifest wiring (WS-C).

## Notes / gotchas

- DedupeBuffer is in `libcalico-go` — changes to it affect Felix and confd;
  prefer not to change its semantics at all. If something is missing, extend
  via new methods, and run `felix` daemon-adjacent UTs.
- The felix pipeline's `NodeCounter` feeds the connection-rebalance math
  (`typha/pkg/k8s/rebalance.go`); it keeps working unchanged since it sits
  downstream of the buffer.
- gob + `SerializedUpdate` round-trips through a chained typha involve
  deserialize→validate→re-serialize (`snapcache` calls `SerializeUpdate`).
  Watch for `Revision any` round-trip fidelity (string vs struct revisions) —
  there is prior art in `syncproto` tests; add a UT asserting revision types
  survive the B-hop.
