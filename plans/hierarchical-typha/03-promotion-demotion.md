# WS-C: Promotion/demotion state machine (self-organising single-tier hierarchy)

## Goal

Wire WS-A's swappable syncer sources to WS-B's election result so a Typha
deployment self-organises: the elected leader runs real datastore syncers;
every other Typha connects to the leader as a Typha client. Promotion and
demotion happen **in-process** (no restart), reconciling through the dedupe
buffers so downstream clients ride through with at most a brief re-sync and
never see an empty/torn snapshot.

End state of this WS = Milestone M2: deployable single-tier hierarchical Typha
behind `TYPHA_HIERARCHYENABLED`.

## Required reading

- `plans/hierarchical-typha/00-overview.md` (binding decisions 1, 5)
- `plans/hierarchical-typha/01-chained-typha-core.md` — `SyncerSource`
  contract; dedupe-buffer-at-head pipeline
- `plans/hierarchical-typha/02-leader-election.md` — `Elector` API,
  dual-leadership window caveat
- `typha/pkg/daemon/daemon.go` — pipeline construction & `Start()`
- `libcalico-go/.../dedupebuffer/dedupe_buffer.go` — reconciliation semantics
- `typha/pkg/discovery/discovery.go` — `WithPostDiscoveryFilter`,
  `ConnectionAttemptTracker`
- `typha/pkg/syncserver/sync_server.go` — `ShutDownGracefully()` (~685),
  graceful drain (~597-652)
- `felix/fv/infrastructure/typha.go` + `topology.go` — FV topology support

## Design

### Role manager

One goroutine per Typha process (`typha/pkg/daemon` or new
`typha/pkg/rolemanager`) consuming `Elector.Roles()`:

```
            ┌────────────┐  Leader role   ┌──────────────┐
   start ──→│  FOLLOWER  │───────────────→│   LEADER     │
            │ (upstream  │←───────────────│ (real        │
            │  sources)  │  Follower role │  syncers)    │
            └────────────┘                └──────────────┘
```

Transition procedure (identical shape both directions), per pipeline ×4:

1. `oldSource.Stop()` — blocks until no more callbacks can be delivered into
   the dedupe buffer (the `SyncerSource.Stop` contract from WS-A; this
   ordering is what makes the next step race-free).
2. `dedupeBuffer.OnTyphaConnectionRestarted()` — buffer snapshots its live-key
   set and discards queued in-flight updates.
3. `newSource.Start(ctx)` — fresh source delivers `WaitForDatastore →
   ResyncInProgress → snapshot → InSync`; at `InSync` the buffer synthesizes
   deletes for keys that vanished while we were switching. Downstream
   (validator → snapcache → connected clients) sees a normal resync, exactly
   like a Felix riding a Typha restart today.

Notes:

- Run the four pipeline transitions concurrently but make the role manager
  strictly serial per role change (a single goroutine; new role events during
  a transition are queued — process only the latest).
- Rapid flap protection: debounce role changes (e.g. don't start a transition
  until the role has been stable for ~2s, configurable) and never interrupt a
  transition mid-flight — finish, then evaluate the latest desired role.
- During the dual-leadership window (see WS-B) two Typhas may briefly both run
  real syncers. This is safe (both serve correct data); the loser demotes when
  it observes leadership loss.
- The leader keeps serving regular clients in this milestone. (Decided:
  who-connects-to-the-leader is policed client-side and only restricted once
  tiering is active — see overview and WS-E. In single-tier M2 deployments
  any client may use the leader.)
- Demoted leader → follower must not connect to **itself**; see discovery
  below.

### Leader discovery for followers

Followers need the leader's address. Holder identity = pod name (WS-B). Two
options:

1. **(Recommended) Leader self-labels its pod** with
   `projectcalico.org/typha-role: leader` (and removes it on demotion /
   graceful exit via pre-stop ordering), plus a new headless Service
   `calico-typha-leader` selecting on that label. Followers use the existing
   `typha/pkg/discovery` against that service — zero new discovery code, and
   it generalises directly to tiers in WS-E. Needs RBAC: `patch` on `pods`
   (restrict via `resourceNames` impossible for own-pod-only; document the
   grant). Edge cases: label lingers if leader is SIGKILLed → endpoint goes
   stale; mitigated because the pod's endpoints disappear when the pod dies,
   and a live-but-demoted pod removes its own label on demotion.
2. Followers resolve `Elector.CurrentHolder()` (pod name) → pod IP via the
   k8s API and use `discovery.WithAddrOverride`. Less moving parts, but
   re-implements endpoint watching and doesn't generalise to WS-E.

Implement (1) unless something blocks; keep the labelling logic in the role
manager (promote: label before starting real syncers? — order matters:
label **after** the real syncers reach InSync, so followers don't connect to a
leader that isn't ready to serve fresh data; readiness gating on the Service
endpoint achieves the same if the leader's readiness reflects sync status —
choose one mechanism and document it).

Cycle/self-connection prevention:

- Post-discovery filter drops our own pod IP (compare against
  `TYPHA_PODNAME`'s pod IP / local addresses) — extends WS-A's guard.
- Followers only ever connect to the leader service in M2, so follower→
  follower cycles are impossible by construction. Assert anyway (filter out
  any endpoint that isn't the current lease holder when holder is known) and
  log loudly.

### Client-facing behaviour during transitions

- snapcache keeps serving the last breadcrumb during a source swap; status
  visible to clients via `MsgSyncStatus` (they'll see ResyncInProgress →
  InSync). Felix's dedupe buffer absorbs it. No client disconnect required.
- **Readiness**: follower is Ready only when all four caches are InSync
  (existing snapcache health reporters already encode this — verify the
  aggregation works when sources swap, i.e. reporters don't get stuck on
  timeout during a transition).
- **Graceful shutdown ordering** (leader): release lease first (triggers
  follower failover early), then existing connection drain
  (`handleGracefulShutDown`). Wire into the daemon's shutdown path.

### Bootstrap

Cold cluster start: all Typhas start as followers with no leader → election
picks one → it promotes (its sources start as none/idle, so "stop old source"
is a no-op on first transition — make the state machine's initial state
SOURCELESS rather than FOLLOWER to keep this clean) → labels pod → followers
discover and sync. Until then followers are not Ready, which is correct.
Verify the calico-typha main Service still selects all typhas so Felix can
connect to any of them once Ready (felix-side preference work is WS-E).

Also handle: hierarchy enabled but election disabled/misconfigured → fatal at
startup with a clear message.

### Config

- `HierarchyEnabled` now implies election required (relaxes WS-A's static
  `UpstreamAddr`, which remains supported for tests/manual chaining and takes
  precedence with a warning).
- `RoleTransitionDebounce` (default ~2s).
- Chart: enable flag plumbed as values option (default off), leader Service
  manifest, RBAC additions (`pods` patch), `gen-manifests`.

## Tasks

1. Role manager skeleton + `SOURCELESS/FOLLOWER/LEADER` states, driven by a
   fake elector in UTs; transition procedure against fake sources verifying
   the Stop → OnTyphaConnectionRestarted → Start ordering and
   no-interleaved-callbacks invariant (race detector).
2. Pod self-labelling + leader Service + follower discovery via it;
   self/non-leader endpoint filtering.
3. Daemon integration: hierarchy mode builds both source kinds per pipeline,
   role manager owns swaps; shutdown ordering (lease release first).
4. Readiness audit across transitions.
5. Chart/RBAC/manifests; values-gated.
6. typha fv-tests: in-process promotion/demotion (see matrix).
7. Felix FV: extend `felix/fv/infrastructure` to run N typhas with hierarchy
   enabled (needs a kube datastore topology — check `infrastructure.K8sDatastoreInfra`),
   kill the leader, assert felixes converge and dataplane stays programmed.
8. DESIGN.md update (role state machine diagram, ordering invariants,
   dual-leader window analysis).

## Test matrix (same PR)

- **UT (most important)**: transition correctness with concurrent updates
  flowing — property: client of the transitioning Typha ends with exactly the
  upstream-truth KV set after promote and after demote, including
  keys deleted-during-transition (extend WS-A's chained harness; this is the
  in-sync-reconcile path under real swap, not just reconnect).
- **UT**: flap storm (role toggling every 100ms for 10s) → no goroutine leaks,
  no deadlock, converges to final role; race detector clean.
- **fv-tests**: 3-harness setup — datastore-fed leader harness, follower
  harness, client; promote the follower (kill leader's lease in a fake
  elector), verify the follower stands up real syncers (fed by the test
  decoupler) and its client reconciles.
- **Felix FV**: 2-3 typhas + 2 felixes, hierarchy on: leader kill →
  re-election → all felixes back InSync; policy programmed during the outage
  appears after recovery. Plus rolling-restart of the whole typha deployment.

## Acceptance criteria

- M2 demo: `kubectl delete pod <leader>` on a hierarchy-enabled deployment →
  new leader within ~LeaseDuration + resync; Felix connections survive
  (reconnect at worst); no client ever observes an empty snapshot marked
  InSync.
- Hierarchy off → zero diff (suites green).

## Out of scope

Tier-1 slots, felix-side tier preference (WS-E); checksums (WS-D).
