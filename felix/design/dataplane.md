<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->


# Felix Linux dataplane — Design

Felix's Linux dataplane is a **single codebase** (`InternalDataplane`
in `dataplane/linux/`) switched between **iptables, nftables and
eBPF** modes — `BPFEnabled`/`NFTablesMode` select which managers and
behaviours are wired into the *same* object. All three modes share
the manager/driver model, the main event loop, the
`OnUpdate`/`apply()` cycle, and the restart-and-resync doctrine.

This doc owns that shared architecture (all three modes) plus the
`*tables` (iptables/nftables)-specific parts — the `Table`
abstraction, rule generation and dispatch chains, IP sets. eBPF mode
reuses the shared architecture but adds its own managers (notably
`bpfEndpointManager`), BPF maps and packet path, documented in the
`bpf-*` family (start at [`bpf-overview.md`](./bpf-overview.md)); a
BPF change typically needs *both* docs. Windows is a separate
dataplane, covered here only as a contrast.

Read this file before editing `felix/dataplane/linux/`,
`felix/iptables/`, `felix/nftables/`, `felix/generictables/`,
`felix/rules/`, `felix/ipsets/`, `felix/markbits/`,
`felix/routetable/`, `felix/routerule/`, or `felix/vxlanfdb/` (plus
the `bpf-*` family for BPF-specific files). The input boundary — the
protobuf messages the dataplane receives — is the other end of the
contract in [`calc-graph.md`](./calc-graph.md); the
[dataplane API section below](#the-dataplane-api-calc-graph--dataplane-contract)
is where that contract is written down. Build/test commands are in
[`felix/CLAUDE.md`](../CLAUDE.md); the whole-Felix overview is in
[`felix/DESIGN.md`](../DESIGN.md).

## Conventions

- "WEP"/"HEP" = workload/host endpoint. "Local" = hosted on this
  node.
- "`*tables`" means the legacy netfilter dataplane, **iptables or
  nftables** — any non-BPF Linux dataplane Felix can program. Where
  a statement is backend-specific the backend is named.
- "**Manager**" and "**driver**" are the two layers this doc keeps
  distinguishing — see Layer roles. File paths are repo-relative;
  type/function/field names are cited, line numbers omitted.

## Layer roles

The calc graph → managers (convert) → drivers (reconcile) layering,
and the dataplane's other jobs — reacting to interface changes,
detecting drift, reporting programming status — are described in
[`DESIGN.md` §1](../DESIGN.md#dataplane-managers-and-drivers). This
section covers where the manager/driver boundary flexes.

The split is not rigid. Some managers are **vertically integrated**
(manager and reconciliation logic in one object); others are split
with shared reconciliation logic in a driver. The
`bpfEndpointManager` is the extreme case — a combined
manager+driver whose reconciliation is complex enough that the two
roles are tightly coupled. When you can, prefer the split: let a
driver absorb the resync complexity behind a declarative
"here is the desired state" API and keep the manager simple (see
[Restart, resync and mark-and-sweep](#restart-resync-and-mark-and-sweep)).

### Review notes for this section

- A new feature that programs kernel state belongs in a manager
  (conversion) and, if it needs reconciliation, a driver — not
  smeared across the event loop. Prefer the declarative
  manager + reconciling driver split; reach for the integrated
  `bpfEndpointManager` style only when the coupling is genuinely
  irreducible.

## The OnUpdate / apply() split

Every manager implements the `Manager` interface
(`dataplane/linux/int_dataplane.go`):

```go
type Manager interface {
    OnUpdate(protoBufMsg any)
    CompleteDeferredWork() error
}
```

(Extended interfaces: `ManagerWithRouteTables`,
`ManagerWithRouteRules` expose route syncers to the loop;
`UpdateBatchResolver` lets a manager resolve cross-manager state
before any programming begins.)

**`OnUpdate` must be cheap and must not perform kernel I/O** (no
netlink call, `iptables-restore`, subprocess fork, or BPF map
write). It
*may* push desired state into the in-memory `ipsets`/
`generictables.Table` objects, which *queue* the change (the
`Manager` doc-comment permits this; `masqManager.OnUpdate` does
exactly this via `AddMembers`/`UpdateChain`). The pattern: stash the
message and **mark the affected resources dirty**; all reconciliation
and kernel mutation happen later in `CompleteDeferredWork()`, walking
the dirty set.

Why the split:

1. **Batching is far cheaper.** Many operations cost the same for one
   change or many — legacy iptables ships the *whole* ruleset to
   userspace and back per change; an IP-set update forks a
   subprocess. Doing the heavy work once per `apply()` over a
   coalesced batch (Felix throttles `apply()` under load so batches
   grow) is the difference between keeping up and not.
2. **It separates safe-anytime work from must-wait work.** In-memory
   updates are safe before in-sync; touching the kernel is not (see
   [resync](#restart-resync-and-mark-and-sweep)).

### Review notes for this section

- Any kernel access (netlink call, `iptables-restore`, subprocess
  fork, BPF map write) in an `OnUpdate` is a bug. It belongs in
  `CompleteDeferredWork`. Flag it.
- `OnUpdate` that does work proportional to anything other than the
  size of the single message is suspect — the point is to be cheap
  and defer.

## The apply() event loop

`InternalDataplane.apply()` (`dataplane/linux/int_dataplane.go`) is
the throttled reconciliation cycle. The message-receive loop fans
each protobuf message out to every manager's `OnUpdate`, then
schedules an `apply()`; under load, applies are rate-limited so
messages coalesce into bigger batches.

`apply()` runs in a deliberate order, because dataplane resources
have dependencies on each other — most importantly **iptables rules
reference IP sets**, and the kernel refuses both to create a rule
referencing an unknown IP set and to delete an in-use IP set. The
order is:

1. Clear `dataplaneNeedsSync`; it will be re-set if anything fails.
2. **Resolution pass** — give every manager (via
   `UpdateBatchResolver`) a chance to resolve cross-manager state
   from the batch. This can produce an update from one manager to
   another (e.g. an endpoint manager telling the BPF endpoint
   manager about a HEP) that **must** land before either starts
   programming.
3. **Programming pass** — call `CompleteDeferredWork()` on every
   manager.
4. **XDP** — applied inline right after the programming pass (not a
   queued resync), every `apply()`; only its `QueueResync` is gated
   on `forceXDPRefresh`. This is Felix's **legacy** XDP —
   untracked-policy XDP layered on iptables mode (`xdpState`), no
   longer enhanced — not the modern XDP path in the proper BPF
   dataplane (see the `bpf-*` design family). Don't confuse the two.
5. Handle any popped **refresh timers** by **queueing resyncs**:
   `forceRouteRefresh` resyncs the route tables, the routing rules,
   **and the VXLAN FDBs**; `forceIPSetsRefresh` resyncs the IP sets.
6. **Create/update IP sets** — but **defer IP set deletions** until
   after the tables are updated.
7. Update VXLAN FDB and link-address entries.
8. **Update route tables and routing rules in parallel** (their own
   goroutines), to overlap their latency with the table work.
9. **Update `*tables`**, now that referenced IP sets exist.
10. **Delete the deferred IP sets**, now that no rule references
    them.
11. **Join** the parallel route/rule work before returning.

If any step fails, the manager/driver keeps its pending state, the
loop sets `dataplaneNeedsSync`, and `apply()` will run again. The
[failure philosophy](#failure-philosophy) below governs how far a
single failure is allowed to halt the rest of the cycle.

The IP-set ordering in steps 6/9/10 is **the dataplane half** of the
cross-layer "never reference an IP set before it's programmed"
invariant; the calc graph's flush order is the other half (see
[IP sets](#ip-sets)).

### Review notes for this section

- A change to the `apply()` ordering must preserve: IP set creates
  before `*tables`; IP set deletes after `*tables`; the resolution
  pass before the programming pass. Re-ordering these silently
  breaks the dependency invariants and only fails under specific
  timings.
- New per-`apply()` work that isn't gated on a dirty flag (i.e.
  runs even when nothing changed) erodes the throttling benefit.
  Walk the dirty set, don't rescan the world every cycle.

## Failure philosophy

Error handling in the loop is, by the maintainers' own assessment,
a relatively weak area of the architecture — treat changes here
with care. The governing principles:

- **Minimise blast radius.** Where there is no ordering constraint,
  a failure programming one resource must not abort the rest. If
  programming route A fails, still attempt B, C, D; keep A dirty;
  retry on the next cycle. Most drivers work this way.
- **Block when continuing would violate a dependency or a security
  interlock.** Sometimes you *must* stop: if resource A can't be
  programmed and the next manager will program something that
  depends on A — or proceeding out of order would break a security
  interlock (e.g. opening traffic before its policy is in place) —
  the loop has to hold off rather than press on.
- **Fail closed, and ultimately panic, where limping on is
  dangerous.** It is not safe to keep running if `*tables`
  programming **consistently** fails, because that can leave the
  node open. After retries are exhausted, Felix gives up and
  panics rather than run indefinitely in an unknown, possibly
  insecure state.

### Refresh timers vs error-triggered resync

These are distinct mechanisms with overlapping effect:

- **Error-triggered resync**: a failed `apply()` leaves work dirty
  and re-runs soon. The re-run is paced by the leaky-bucket
  `applyThrottle` (with a ~10s `retryTicker` as a backstop), not by
  exponential backoff; exponential backoff is only used *inside*
  the iptables `Table.Apply()` loop. This recovers from transient
  failures.
- **Periodic refresh** (`forceRouteRefresh`, `forceIPSetsRefresh`,
  XDP): on a timer, queue a resync on the drivers even when
  nothing is known to be wrong. This is the belt-and-braces defence
  against **drift Felix didn't cause and wasn't told about** — the
  drift-detection job noted in
  [`DESIGN.md` §1](../DESIGN.md#dataplane-managers-and-drivers).
  Most drivers resync everything in one pass. The **legacy ipsets
  driver is the exception**: a periodic refresh there is satisfied
  *incrementally* over several apply loops (see
  [IP sets](#ip-sets)), because re-listing every set at once is too
  slow. Start-of-day and error-triggered ipset resyncs stay full and
  synchronous.

### Review notes for this section

- A change that lets `apply()` press past a failure must confirm it
  isn't crossing a dependency or security interlock — the case
  where blocking is mandatory.
- A change that swallows a `*tables` programming error (rather than
  keeping it dirty / eventually failing loudly) risks leaving the
  node silently open. The fail-closed-then-panic behaviour for
  persistent `*tables` failure is intentional; don't soften it
  without a strong argument.

## Restart, resync and mark-and-sweep

This doctrine shapes every driver and is the part most often gotten
wrong when adding a feature that creates kernel state.

**Felix must be restartable at any moment** (upgrade, config change,
crash) and, on restart, **resync with the dataplane and converge to
the current desired state with minimal disruption** — including
cleaning up resources created by a *previous* Felix instance whose
datastore state may have been completely different. The restarted
Felix has **no memory** of what the old one did and gets **no**
"resource X was deleted" event for state the old Felix created but
the new datastore no longer wants.

Two consequences:

1. **Cleanup is deferred until in-sync.** The dataplane does not
   touch the kernel until it receives the first datastore in-sync
   signal, and the first `apply()` after that is what triggers
   cleanup. If it swept earlier it would delete state it simply
   hadn't been told about yet. (This is why the calc graph must
   never fabricate in-sync — see
   [`calc-graph.md` → In-sync semantics](./calc-graph.md#in-sync-semantics).)
   Several drivers are architected so the *first* `Apply()`/resync
   call performs the read-back-and-reconcile.
2. **Every driver must identify its own resources.** To mark-and-
   sweep — keep what's still wanted, delete the orphans — a driver
   must be able to look at the live kernel state and decide "this
   one is mine and unwanted" **without** the original datastore
   state and **without** a delete edge-trigger — including state
   written by an *earlier Felix version*, whose naming or format may
   have changed across the upgrade.

Therefore: **any feature that creates a new kind of kernel resource
must, up front, design how a freshly-restarted Felix will recognise
that resource as Calico's, for later cleanup.** This is a
first-class design question, not an afterthought.

### How each subsystem identifies "ours"

The kernel subsystems differ a lot in what they support, which is
why the identification mechanism differs per driver:

| Subsystem | How Felix recognises its own state |
|---|---|
| iptables (`iptables/`) | A **rule comment with our prefix and a hash of the input rule**. Needed because `iptables-save` output does **not** round-trip — the kernel re-canonicalises some constructs and the tools reformat others (the one concrete documented case is TCP-flag matches, per `iptables/actions.go`; MARK/CONNMARK are rendered to round-trip). The comment lets Felix (i) identify Calico rules even outside Calico-owned chains, and (ii) detect drift: read-back hash ≠ desired hash ⇒ reprogram. (Does not defend against malicious tampering that preserves the comment — out of threat model.) |
| nftables (`nftables/`) | Inherited the iptables hash/prefix approach for porting ease, but doesn't strictly need it: **if it's in our table, it's ours.** A future simplification. |
| ip rules (`routerule/`) | No marking support. Identified by **the tables they jump to being Felix-owned**. Imperfect — a config change can confuse it. |
| routes (`routetable/`) | Heuristic, because the first implementation didn't uniformly use the route `proto` field (it should have): **in a Felix-owned table ⇒ ours; carries our proto ⇒ ours; points down a `cali`-owned veth ⇒ ours**; etc. The classifier is the `OwnershipPolicy` interface — `MainTableOwnershipPolicy.RouteIsOurs`/`IfaceIsOurs` in `routetable/ownershippol/`. (Not to be confused with `RouteClass`, which is a same-CIDR conflict tie-breaker among *desired* routes, not an ownership test.) |
| IP sets, iptables chains, veths | Identified by **name prefix** (`cali`...). |

### Review notes for this section

- **A key review question for any PR that creates new
  dataplane state:** "How does a freshly-restarted Felix, with no
  memory and possibly a totally different datastore, recognise this
  as ours to sweep — with no delete event and no prior state?" If
  the PR doesn't answer it, it has a latent leak across restart.
  The menu of mechanisms is the table above (hash-comment /
  owned-table / owned-proto / name-prefix); pick one and wire in
  the read-back.
- A change that makes a driver mutate the kernel before in-sync
  defeats the deferred-cleanup safety and risks deleting
  not-yet-seen state.

### Fail closed while Felix isn't running

Recognising "our" resources is not only about cleanup — it is also
**security-critical**, because the dataplane has to keep doing the
right thing in the windows when Felix is **down, restarting, or
behind**. The motivating race:

- Calc-graph updates can be delayed (Felix busy, restarting, or
  crashed).
- The CNI plugin creates a new workload's `cali*` veth and plugs in
  the pod **before** that endpoint round-trips through the datastore
  back to Felix — so for a moment the interface exists but Felix has
  no policy for it.

Therefore the iptables/nftables dispatch chains (the
[dispatch trie/map](#rules-generation-dispatch-chains-and-mark-bits))
**fail closed**: they **drop traffic to/from any `cali*` interface
that isn't explicitly allow-listed**. This is a Felix responsibility,
not the CNI plugin's: the CNI plugin relies on Felix having *already*
programmed that catch-all drop rule, so a freshly-plugged veth carries
no traffic until Felix programs its policy — and the rule stays in the
kernel even if Felix is stopped entirely.

The general doctrine, which applies to any dataplane change: **think
about what happens if Felix crashes or stops at this exact point.**
Existing, already-secured traffic must keep flowing; anything that
can't yet be secured properly must fail closed, not fall open.

## The dataplane API (calc graph → dataplane contract)

This section is the one place the calc-graph→dataplane contract is
written down; [`calc-graph.md`](./calc-graph.md) links here for the
consumer view, and documents the producer-side ordering machinery
(the `EventSequencer`).

- **Transport.** The interface is the set of `proto.*` messages in
  [`felix/proto/`](../proto/), delivered to managers' `OnUpdate`. It
  exists because Felix was split Python→Go along this seam during a
  rewrite; the protobuf encoding is an artefact of that history.
- **Mostly internal, one external consumer.** The API is
  essentially internal to Felix, with **one friendly out-of-tree
  consumer: the VPP dataplane**, which consumes the protobuf-encoded
  stream. There is **no formal stability guarantee**, but changes
  aren't made willy-nilly — the convention is to give the VPP team a
  heads-up ("we're refactoring this, would it break you?") before
  changing the wire shape.
- **Ordering guarantees the dataplane may rely on.** The
  `EventSequencer` flushes in dependency-safe order, so the
  dataplane may assume **references arrive before referents and are
  removed after them**: IP sets before policies, policies/profiles
  before the endpoints that reference them, VTEPs before routes. The
  authoritative ordering and its rationale are in
  [`calc-graph.md` → Flush order is the dependency contract](./calc-graph.md#flush-order-is-the-dependency-contract).
- **In-sync.** No kernel mutation before the first in-sync; see
  [Restart, resync and mark-and-sweep](#restart-resync-and-mark-and-sweep).
- **The exceptions.** The "references before referents" rule has
  sanctioned exceptions for genuinely-missing resources (e.g. the
  fail-safe deny-all profile), documented on the producer side in
  [`calc-graph.md` → The missing-resource tension](./calc-graph.md#the-missing-resource-tension);
  a dataplane that consumes a pass-through signal owns the receiving
  half.

### Review notes for this section

- A change to a `proto.*` message shape (field added/removed/
  repurposed, message semantics changed) is a change to this
  contract: update this section and
  [`calc-graph.md`](./calc-graph.md), and consider the VPP
  consumer — flag it for a heads-up.
- A dataplane change that starts relying on a *new* ordering
  property not guaranteed by the flush order is a contract change,
  not a local change — it must be backed by an `EventSequencer`
  guarantee, not by incidental current behaviour.

## The `*tables` Table abstraction

The iptables (`iptables/table.go`) and nftables (`nftables/`) `Table`
types, over the shared `generictables.Table` interface, own
reconciliation of `*tables` chains and rules. The model:

- **Felix owns named `cali-*` chains outright** and reconciles them
  to the desired contents. Into kernel-owned chains it **inserts**
  (or appends) only its own jump rules and recognises them by hash
  comment (see [identification](#how-each-subsystem-identifies-ours)).
- **Desired vs actual is reconciled by rule hash.** Each rule
  carries a hash of its intended content (`generictables.RuleHasher`);
  on resync Felix reads back, compares hashes, and reprograms only
  what differs — giving minimal-delta, non-disruptive updates.
- **`iptables-restore` is used for performance and atomicity.**
  Applying the whole update through one `iptables-restore` is much
  faster than issuing individual `iptables` calls, and lands as a
  single atomic per-table transaction (see the goals comment in
  `iptables/table.go`). Note this does *not* make full rewrites
  free: Felix still computes the hash delta and reprograms only
  changed rules, partly to avoid resetting iptables packet/byte
  counters on rules that didn't change.

### iptables vs nftables: parity and divergence

The two backends are kept behaviourally aligned, but parity is a
**deliberate decision, not an automatic requirement**:

- A new feature that's trivially the same function on both ⇒
  implement on both; that's the path of least resistance.
- A feature with significant per-backend differences, or absent
  from one backend, ⇒ a design decision to agree, not a default.
  Expect more nftables-only (and BPF-only) features over time.
- nftables is gradually migrating to **nft-native constructs**
  (e.g. match-action maps) for performance/scale wins, leaving
  iptables users no worse off.

### Review notes for this section

- A PR adding `*tables` rule semantics must first decide the
  iptables/nftables story explicitly (both? nft-only? — see above),
  and should carry FV coverage in the relevant mode(s)
  (`make fv` and/or `make fv-nft`).
- A change to how rules are hashed or how Calico rules are
  recognised touches the restart/resync identification mechanism —
  review it against [mark-and-sweep](#restart-resync-and-mark-and-sweep),
  not just the happy path.

## Rules generation, dispatch chains and mark bits

[`felix/rules/`](../rules/) is the `*tables` rule-rendering layer: it
converts lists of Calico-internal rules/endpoints/etc into concrete
`*tables` rules.

- **Dispatch chains avoid O(n-endpoints) per-packet cost.**
  Evaluating an iptables rule costs on the order of a microsecond
  (rough estimate; no in-repo benchmark), so a flat chain of 100+
  per-endpoint dispatch rules is a real per-packet tax. This really is
  per-*packet*, not per-connection: the conntrack accept lives in the
  per-endpoint chain, downstream of dispatch, so even established flows
  traverse the dispatch chains (an earlier short-circuit further up the
  path was moved into the per-endpoint chain because it broke setups
  with non-Calico rules). Felix builds
  a **shallow (typically single-level) tree of dispatch chains**,
  binning endpoints by the next character after the common
  interface-name prefix (`sortAndDivideEndpointNamesToPrefixTree` /
  `buildSingleDispatchChainTree` in `rules/dispatch.go`): roughly one
  branch per distinct next-character rather than one rule per
  endpoint. This is the `*tables` analogue of the BPF fast-path
  discipline: keep per-packet work sub-linear in the number of local
  endpoints. The dispatch chains also **fail closed**: a `cali*`
  interface that isn't in the trie is dropped, which is the
  security-critical default that protects not-yet-known workloads
  (see [Fail closed while Felix isn't running](#fail-closed-while-felix-isnt-running)).
- **Mark-bit allocation.** Marks are a scarce, shared resource.
  `MarkBitsManager` (`felix/markbits/`, e.g. `NextSingleBitMark`)
  allocates bits for `*tables` modes from the configured range. (BPF
  uses a *fixed*, congested range whose individual bits are managed
  in a BPF header file — see the BPF design family.) An allocation
  that exhausts the range, or collides with bits another subsystem
  expects, is a startup/runtime failure.

### Review notes for this section

- A PR that adds a dispatch rule per endpoint to a flat chain
  reintroduces the linear per-packet cost the tree structure exists
  to avoid. Keep new per-endpoint matching inside the tree.
- A PR that claims a new mark bit must allocate it through
  `MarkBitsManager` against the configured range, and must not
  assume a specific bit is free. The Enterprise build allocates
  further bits from the same range, so a bit that looks free here may
  collide there — check downstream before adding one.

## IP sets

[`felix/ipsets/`](../ipsets/) reconciles kernel IP sets against
desired membership. Three behaviours look odd until you know the
kernel constraints behind them:

- **Temp-set-and-swap.** Atomically changing the capacity or metadata
  of an **in-use** IP set is only possible by building a temporary set
  and swapping it in. That's why updates that change set parameters go
  via a temp set.
- **Deletions are deferred until after `*tables` updates.** You
  cannot delete an in-use IP set, so a set being removed must first
  have every referencing rule removed — which the `apply()` ordering
  (delete IP sets *after* `*tables`) guarantees.
- **Deletions are rate-limited/queued** because each `ipset destroy`
  is surprisingly slow (~40ms) and serialised in the kernel: Felix
  caps deletions per iteration (`MaxIPSetDeletionsPerIteration = 1`,
  rescheduling with a ~100ms floor), so a big policy teardown of
  thousands of sets doesn't stall the whole dataplane on cleanup.
- **Periodic resyncs are incremental**, for the same reason. Felix
  reads back each set with its own `ipset list <name>` (needed for an
  ipset compatibility issue), so re-listing every set on each refresh
  is far too slow. A refresh instead lists only the *names* cheaply,
  repairs any set that vanished or appeared unexpectedly right away,
  and re-checks the surviving sets' contents from a two-tier queue
  (`resyncQueue`) drained a time-boxed batch per apply
  (`BackgroundResyncTimeBudget`), paced by the same ≤100ms reschedule
  as deletions. The **must** tier (start-of-day and error-forced
  resyncs) is drained fully before Felix trusts the dataplane; the
  **background** tier (periodic refresh) is spread over apply loops. A
  desired set found missing from the name listing is repaired in the
  *same* apply — its dataplane view is cleared so the normal
  create-path recreates it — rather than being queued for a wasted
  per-set list. On nodes with many sets the queue may never fully
  drain between refreshes; re-adds keep an entry's queue position, so
  the sweep degrades into a continuous rolling scan and a given set's
  contents are re-checked roughly once per *sweep* time, which can
  exceed `IpsetsRefreshInterval`. That is the intended trade-off, not
  a pacing bug.

**The cross-layer invariant: never reference an IP set before it is
programmed.** This is enforced jointly by the calc graph and the
dataplane, and a change to *either* alone breaks it:

- the **calc graph** always emits an IP set before any policy that
  references it (the `EventSequencer` flush order), and
- the **`apply()` ordering** creates IP sets before `*tables` and
  deletes them after.

### Review notes for this section

- A change to IP-set creation/deletion ordering, in *either* the
  calc graph flush order or `apply()`, must preserve the joint
  "reference only after programmed / delete only after
  dereferenced" invariant. Reason about both layers together.
- A change that deletes IP sets eagerly (not deferred / not
  rate-limited) can hit in-use errors or stall the dataplane on a
  big teardown.
- A change to the incremental resync must preserve three invariants:
  (a) the start-of-day full resync completes before the first writes;
  (b) a desired set found missing from the name listing is repaired in
  the same apply as the sweep that finds it; (c) a set whose write
  failed is re-checked at **must** priority before Felix writes to it
  again.

## Routing drivers

[`felix/routetable/`](../routetable/),
[`felix/routerule/`](../routerule/) and
[`felix/vxlanfdb/`](../vxlanfdb/) are drivers in the sense above:
managers (`vxlanManager`, `ipipManager`, `wireguardManager`,
`noEncapManager`, …) compute desired routes/rules/FDB entries and
hand them off; these drivers reconcile against netlink.

They follow the same doctrine as the rest of the dataplane —
start-of-day resync, minimal-disruption deltas, mark-and-sweep of
orphans — but with the **weakest identification story** (see the
[identification table](#how-each-subsystem-identifies-ours)): routes
by a heuristic blend of owned-table / owned-proto /
points-down-a-cali-veth, ip rules only by the tables they jump to.
That makes ownership classification and resync correctness the
delicate part of any change here.

> The deep netlink-level design of route resync (grace periods for
> CNI races, conntrack cleanup on IP moves, etc.) is large enough to
> warrant its own future sub-design; this section covers only how
> the route drivers fit the dataplane architecture.

### Review notes for this section

- A change to route/rule ownership classification can make Felix
  either delete routes it shouldn't (too greedy) or leak routes a
  previous Felix left (too timid). Review against the restart
  scenario, not just steady state.

## Dual stack

The manager/driver topology **mirrors the kernel's structure**.
Because the Linux kernel runs IPv6 largely as a separate plane,
Felix instantiates a **second copy** of the managers and drivers for
IPv6, and the two are ships in the night — IPv4 and IPv6 updates can
often run in parallel for that reason.

The standard failure here is touching only the IPv4 instance.
Legitimate asymmetries are rare on the `*tables` path. Two notes:

- **BPF is the exception** to the two-separate-planes model: its
  entrypoint programs receive both families and fan out internally
  to v4/v6 sub-programs.
- **nftables** could in principle have used a single shared v4/v6
  table, but was kept as two to track the iptables structure for
  porting ease.

### Review notes for this section

- A dataplane change must be applied symmetrically to the IPv4 and
  IPv6 manager/driver instances unless there's a specific reason not
  to. "Works on v4, forgot v6" is a recurring bug.

## Windows (contrast)

Windows has its own dataplane (`dataplane/windows/`) and a full
design is out of scope here, but it's worth recording what carries
over and what doesn't, because it sharpens the Linux model:

- **What's the same:** the overall architecture. Windows still defers
  programming until in-sync, still aims for minimal-disruption
  reconciliation, still resyncs at start of day.
- **What differs:** the HCN/HNS dataplane has **no IP-set
  primitive**, so the Calico IP-set model doesn't fit. The
  Calico→kernel conversion that on Linux is split across managers and
  drivers is instead done by **calc-graph-like flattening functions
  inside the Windows dataplane**, converting policies + IP sets into
  fully-flattened HCN rules. It's isolated there deliberately.
- **A sharp edge:** the HCN dataplane causes **traffic disruption on
  *any* rule change**, so the "don't flap already-correct resources
  on resync" rule (below) matters even more on Windows than on
  Linux.

## How to write a manager (and common failure modes)

The recurring ways dataplane changes go wrong, and the recipe that
avoids most of them.

**Start simple: dirty-flag + start-of-day resync.** For a
low-traffic manager, don't try to handle each individual update
incrementally. Code the start-of-day resync first, driven by a single
`dirty` bool:

1. Initialise `dirty = true` so the resync runs on the first
   in-sync `apply()`.
2. On any relevant `OnUpdate`, stash the data and set `dirty`.
3. In `CompleteDeferredWork`, if `dirty`, reconcile the whole thing
   and clear it.

That's often all a low-traffic manager needs. Even when it's not the
most efficient possible design, it's a **100%-correct** one — enough
to write the `felix/fv` FV tests against and optimise later.

**The hard part is a non-disruptive resync** — reconciling without
flapping resources that are already correct. There's no shortcut:

- Design in a simple **discriminator** for your resources up front
  (a `cali` prefix/comment where supported is ideal) so you can tell
  yours apart — this is the same requirement as
  [mark-and-sweep](#restart-resync-and-mark-and-sweep).
- On resync: read back the kernel state; reconcile it against
  desired; classify into **already-correct / out-of-sync /
  to-delete**; **mark already-correct as done and don't touch it**;
  make minimal least-disruptive changes to out-of-sync resources
  (some disruption may be unavoidable — that's OK *as long as only
  out-of-sync objects are touched*); sweep the orphans.

**The shortcut, where the kernel offers it: atomic full-state
replacement.** If the kernel can atomically replace the whole
resource set and GC orphans itself, you can skip read-back entirely:
compute the full desired state and hand it over atomically. This is
**often the API a driver presents to its manager** even when the
kernel underneath doesn't work that way — the driver absorbs the
read-back/reconcile/cleanup so the manager just declares desired
state. (This is exactly why the manager/driver split pays off.)

BPF map versioning (`felix/bpf/maps/maps.go`) shows the discipline
that goes with this. **By default a map is rebuilt from desired
state at upgrade time**, exactly like every other resync — no
special handling. The copy/migrate path is reserved for maps whose
contents are **sourced by the BPF programs themselves**, not by
Felix — in practice the **conntrack map**. For those,
`PinnedMap.EnsureExists`/`Upgrade` repins the live map aside to
`<path>_old`, builds the new-layout map in the normal pin path,
copies entries across (`CopyDeltaFromOldMap`/`copyFromOldMap`), and
drops `_old` — crash-safe because a restart mid-migration finds
`_old` and rolls forward. The migration logic is fiddly; apply it
only to maps that genuinely can't be rebuilt.

### The failure modes, distilled

1. **Delta-only, no from-scratch resync.** The biggest blind
   spot. A manager that only handles individual updates and never
   reconciles from scratch will leak or diverge across restart. Write
   the start-of-day resync first.
2. **Kernel work in `OnUpdate`.** Breaks batching and the
   safe-before-in-sync boundary. Defer to `CompleteDeferredWork`.
3. **Disruptive resync.** Flapping already-correct resources on
   every resync — connectivity glitches. Classify and touch only
   the out-of-sync.
4. **No restart-time identification.** Creating a resource type with
   no way for a fresh Felix to recognise it ⇒ orphans leak forever.
5. **Forgetting nftables, or BPF mode.** `*tables` rule changes that
   only land on one backend; or forgetting that BPF mode reuses some
   of this code (e.g. parts of `felix/rules/`).
6. **Touching only IPv4.** See [Dual stack](#dual-stack).

### Review notes for this section

- A new manager without a from-scratch resync path (dirty-flag or
  atomic-replace) is incomplete, regardless of how well it handles
  deltas. Ask to see the resync.
- A resync that rewrites or re-adds resources unconditionally
  (rather than diffing and touching only what's wrong) will glitch
  connectivity — push back.

## Keep this document in sync with the code

The repo-wide doc-update rule
([`.claude/CLAUDE.md` → Documentation map](../../.claude/CLAUDE.md),
mirrored in
[`.github/copilot-instructions.md`](../../.github/copilot-instructions.md))
applies. For the Linux dataplane, "changes how it works" means: a
new manager or driver, or a change to the manager/driver split; a
change to the `apply()` ordering or the `OnUpdate`/`CompleteDeferredWork`
contract; a new kind of kernel resource or a change to how Calico
resources are identified for resync; a change to the `*tables` Table
reconciliation, dispatch-chain structure, mark-bit allocation, IP-set
ordering, or route ownership classification; or a change to the
`proto.*` dataplane API. Update the relevant section of this file in
the same PR — and [`calc-graph.md`](./calc-graph.md) too if the
[dataplane API contract](#the-dataplane-api-calc-graph--dataplane-contract)
changes. This file is the source of truth for the Linux dataplane's
invariants.
