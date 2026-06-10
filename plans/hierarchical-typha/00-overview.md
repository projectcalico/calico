# Hierarchical Typha — Master Plan

## Goal

Today every Typha instance connects directly to the datastore (kube-apiserver).
At very high scale (target: up to 1M nodes) we want to remove the datastore as
the fan-out bottleneck by arranging Typhas hierarchically:

- **Leader** Typha: elected via Kubernetes Lease-based leader election; the only
  Typha that runs real datastore syncers. Source of truth.
- **Tier-1** Typhas (highest-scale deployments only): a small, elected set that
  connect to the leader and fan out to the rest.
- **Tier-2 / follower** Typhas: connect to tier-1 Typhas (or directly to the
  leader in single-tier mode) instead of the datastore, and serve Felix and
  other clients.
- Felix and other clients always prefer a Typha on their own node (smooths
  bootstrap), otherwise connect to tier-2 Typhas.

Typha already has everything needed to act as a *server* for other Typhas; the
work is to let Typha act as a *client* of another Typha, to swap between
"client of upstream" and "real syncer" modes on promotion/demotion, and to add
enough integrity checking that we can trust the extra hops.

## Background reading (required for every implementation agent)

- `typha/pkg/syncproto/sync_proto.go` — package doc comment is the
  authoritative description of the Typha protocol, including the **protocol
  upgrade rules** (feature flags in the hello messages; never send a new
  message type the peer hasn't advertised support for) and the decoder-restart
  mechanism. Read the whole comment before touching the protocol.
- Typha architecture/scale design doc (breadcrumb cache, shared binary
  snapshots, why gob, snapshot bottleneck):
  https://docs.google.com/document/d/1OJvKPhccPC-HW4CIF80huzgZWzCLO3VaWwTbl0Q58fI
- `.claude/CLAUDE.md` — repo rules. In particular: tests land in the same PR;
  behaviour changes must update the component DESIGN.md (Typha doesn't have one
  yet — WS-A creates it); generated files committed alongside source.

## Existing building blocks (verified, with refs)

| Block | Where | Why it matters |
|---|---|---|
| Syncer pipelines | `typha/pkg/daemon/daemon.go:263` (`addSyncerPipeline`), `CreateServer():305` | One pipeline per syncer type (felix, bgp, tunnel-ip-allocation, node-status): `Syncer → SyncerCallbacksDecoupler → ValidationFilter (+NodeCounter for felix) → Decoupler → snapcache.Cache`. This is where the upstream source gets swapped. |
| Snapshot cache | `typha/pkg/snapcache/cache.go` | COW B-tree of `syncproto.SerializedUpdate` + breadcrumb linked list. `publishBreadcrumb()` already looks up the old value for each write (dedupe check) — the natural hook for an incremental checksum. |
| Sync client | `typha/pkg/syncclient/sync_client.go` | Full client incl. discovery-driven failover, TLS, compression, decoder restart. `RestartAwareCallbacks` (line 175) defines `OnTyphaConnectionRestarted()`. |
| Dedupe buffer | `libcalico-go/lib/backend/syncersv1/dedupebuffer/` | Implements `RestartAwareCallbacks`; on reconnect snapshots its live-key set and, at the next `InSync`, synthesizes deletes for keys missing from the new snapshot (`onInSyncAfterReconnection()`, line 344). This is the reconciliation engine for both reconnection *and* promotion/demotion. |
| Client wiring template | `typha/pkg/syncclientutils/startsyncerclient.go` | `MustStartSyncerClientIfTyphaConfigured()` shows the canonical syncclient + dedupebuffer wiring (used by confd etc.). |
| Discovery | `typha/pkg/discovery/discovery.go` | EndpointSlice-based; already supports `WithNodeAffinity` (local-first ordering) and `WithPostDiscoveryFilter`. |
| Leader election lib | `k8s.io/client-go v0.36.1` (root `go.mod:108`) | `tools/leaderelection` + `resourcelock.LeaseLock` available; **nothing in the repo uses it yet** — Typha sets the pattern. |
| K8s clientset in Typha | `typha/pkg/k8s/lookup.go:39` (`RealK8sAPI`) | Reusable for leader election and pod-label patching. |
| Deployment/RBAC | `charts/calico/templates/calico-typha.yaml`, `calico-node-rbac.yaml` | Needs Lease RBAC, downward-API POD_NAME/POD_NAMESPACE/NODE_NAME, tier Services. |
| Test harnesses | `typha/fv-tests/server_harness_test.go` (`ServerHarness`), `felix/fv/infrastructure/typha.go` (`RunTypha`, `TopologyOptions.WithTypha`) | In-process server+client harness chains naturally into a two-level hierarchy; Felix FV can run real multi-Typha topologies. |

## Workstreams

| ID | Plan file | Summary | Depends on |
|---|---|---|---|
| WS-A | `01-chained-typha-core.md` | "Chained Typha": Typha can source its caches from an upstream Typha via syncclient + dedupe buffer at the pipeline input. Statically configured (no election yet). Creates `typha/DESIGN.md`. | — |
| WS-B | `02-leader-election.md` | Lease-based leader election via client-go; pod identity plumbing; RBAC; chart changes. No behaviour change beyond logging/metrics (election result unused until WS-C). | — (parallel with WS-A) |
| WS-C | `03-promotion-demotion.md` | State machine wiring WS-A + WS-B: promote = stop syncclients, start real syncers, reconcile via dedupe buffer; demote = reverse. Leader/follower discovery, self-connection and cycle prevention. | WS-A, WS-B |
| WS-D | `04-integrity-checksum.md` | Incremental rolling checksum over the snapcache B-tree, carried in the protocol (negotiated via hello flags); mismatch detection + remediation. | WS-A (independent of WS-B/C) |
| WS-E | `05-two-tier-fanout.md` | N elected tier-1 Typhas (lease slots), tier advertisement via pod labels + per-tier Services, client tier preferences, rebalancing math per tier. | WS-C |
| WS-F | `06-testing-and-rollout.md` | Cross-cutting test strategy (UT, typha fv-tests chains, Felix FV multi-typha topology, scale/soak), metrics, docs, upgrade story, rollout gating. | tracks all |
| WS-G | `07-operator-integration.md` | tigera/operator support (separate repo; local worktree `/home/shaun/go-os/src/github.com/tigera/typha-multi`): RBAC, downward-API env, tier label + Services, typha client cert, Installation API field, autoscaler tier math. | trails WS-C and WS-E |

Dependency graph / suggested milestones:

```
M1: WS-A (chained typha, static config)  ──┐
    WS-B (leader election, inert)        ──┤
                                           ├─→ M2: WS-C (self-organising single-tier hierarchy)
M1.5: WS-D (checksums; mergeable any time ─┘        │
       after WS-A)                                   └─→ M3: WS-E (two-tier, 1M-node mode)
WS-F runs throughout; each milestone has its own test gate.
```

M1 is independently shippable and valuable for testing: `TYPHA_*` config to
point a Typha at a fixed upstream Typha gives a manually-chained hierarchy that
exercises the entire data path without any election machinery.

## Cross-cutting design decisions (binding on all sub-plans)

1. **The dedupe buffer is the stable element.** Each syncer pipeline gets a
   `dedupebuffer.DedupeBuffer` permanently installed at its input. Sources
   (real syncer or syncclient) are swapped *behind* it. Any source swap is
   signalled by calling `OnTyphaConnectionRestarted()` on the buffer, after
   which the new source delivers a fresh snapshot and the buffer reconciles
   (synthesizing deletes at `InSync`). Downstream (validator → snapcache) never
   needs to know a swap happened, and clients of this Typha keep being served
   the last-known-good cache during the transition. No new reconciliation code.
2. **Protocol changes are hello-flag negotiated.** Per the rules in
   `sync_proto.go`: new message types/fields gated on `Supports*` booleans in
   `MsgClientHello`/`MsgServerHello`. Old Felix ↔ new Typha and new Felix ↔
   old Typha must keep working.
3. **One connection per syncer type.** A follower Typha runs up to
   `syncproto.NumSyncerTypes` (4) syncclient connections to its upstream, one
   per pipeline, mirroring how Felix/confd connect today.
4. **TLS is symmetric.** Typha-as-client reuses the existing
   `syncclient.Options` TLS fields (CertFile/KeyFile/CAFile/ServerCN/
   ServerURISAN, verified by `typha/pkg/tlsutils.CertificateVerifier`). New
   `TYPHA_CLIENT*` config params; the upstream's existing `ClientCN`/
   `ClientURISAN` checks must accept the Typha client cert.
5. **Fail safe, serve stale.** A Typha that loses its upstream keeps serving
   its current cache (marked not-in-sync) while reconnecting/re-electing.
   Readiness reflects sync status so orchestration can see it.
6. **Config naming.** New params follow the existing `typha/pkg/config`
   struct-tag pattern; gate everything behind
   `TYPHA_HIERARCHYENABLED` (default off) so the feature is opt-in and the
   default deployment is byte-for-byte unchanged.

## Handoff protocol for implementation agents

Each sub-plan is written to be executed by a single agent (Sonnet/Opus class)
on its own branch. For every sub-plan:

- Read this overview first, then the sub-plan, then the **Required reading**
  list inside it. Line numbers were correct at planning time (branch
  `typha-multi`); re-verify before editing.
- Tests ship in the same PR (repo rule). Each sub-plan lists the minimum test
  matrix; `06-testing-and-rollout.md` holds the shared harness work.
- Update `typha/DESIGN.md` (created in WS-A) in the same PR for any behaviour
  change.
- Chart/manifest changes: edit `charts/`, run `make gen-manifests`, commit
  both. New config params: update config UT + the chart env plumbing.
- Don't change message framing or send unnegotiated message types — see
  binding decision 2.

## Open questions (tracked here, owned by Shaun)

- ~~Should the leader also serve ordinary Felix clients?~~ **Decided (Shaun):
  handle it client-side.** A client on the leader's node must connect to the
  leader (own-node-first rule, all tiers); clients on other nodes are
  forbidden from connecting to the leader (and tier-1) in larger clusters.
  No server-side `LeaderServesClients` knob; the main `calico-typha` Service
  keeps selecting all typhas and clients filter using tier information from
  the per-tier Services. See WS-E.
- Safety valve: should a follower fall back to direct datastore connection if
  no leader is reachable for N minutes? Plan assumes **no** for now (election
  guarantees a leader will emerge; fallback risks a thundering herd on the API
  server — the exact thing we're protecting). Revisit after soak testing.
- Checksum scope for Felix clients (vs Typha-to-Typha only) — see WS-D open
  questions.
