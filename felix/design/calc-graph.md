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


# Felix calculation graph — Design

This is the design doc for Felix's **calculation graph** (the
"brain"): the code under [`felix/calc/`](../calc/) plus the
indexing packages it depends on, [`felix/labelindex/`](../labelindex/)
and [`felix/dispatcher/`](../dispatcher/). It covers what the calc
graph is for, the contract every calculation node must honour, the
contract the graph relies on from upstream, the `EventSequencer`
output stage, and how the whole thing is tested.

If you are editing any of those packages, or reviewing a PR that
does, read this file. The output boundary — the protobuf messages
the graph emits to the dataplane — is documented from the
consumer's side in
[`dataplane.md` → The dataplane API](./dataplane.md#the-dataplane-api-calc-graph--dataplane-contract);
that section and this one are the two ends of the same contract.

Operational guidance (how to build and run the tests) is in
[`felix/CLAUDE.md`](../CLAUDE.md). The architecture overview that
places the calc graph in the wider Felix data flow is in
[`felix/DESIGN.md`](../DESIGN.md).

## Conventions

- "WEP" = workload endpoint, "HEP" = host endpoint. "Local" means
  hosted on this node — the calc graph's whole job is to reduce
  cluster-wide state to this node's local picture.
- "Node" used unqualified in this doc means a **calculation node**
  (a vertex in the graph), not a Kubernetes node. Where it means a
  Kubernetes/host node the text says so.
- A "KV" is a datastore key/value pair as delivered by the syncer:
  a typed key plus a value that is either `nil` (gone / invalid) or
  the current state of that resource.
- File paths are repo-relative. Type, function, field and constant
  names are cited; line numbers are deliberately omitted because
  they rot.

## What the calc graph is for

The calc graph is an **incremental, in-process event pipeline**. It
consumes the eventually-consistent stream of datastore updates from
the syncer and emits a stream of protobuf messages describing the
desired state of *this node's* dataplane, in Calico-internal terms
(local WEPs, resolved policy rules, fully-expanded IP sets, routes,
VTEPs). It is, in effect, a pure function of datastore state —
"given this set of resources in the datastore, here is what this
node's dataplane should contain" — implemented incrementally so it
can keep up with churn.

### The scale it was built for

The original design target was **100k endpoints, ~2k policies, and
churn of ~1000 endpoints/second**, with the dataplane applying the
resulting updates **sub-second**. Those numbers are why the
architecture looks the way it does:

- **Incremental, minimal-delta output.** The dataplane must update
  incrementally with the smallest possible change set and low
  latency. The calc graph therefore processes one datastore update
  at a time and emits only what changed — it never recomputes the
  world.
- **Back-pressure all the way up.** If the calc graph can't keep
  up, or the dataplane can't keep up, the upstream layers block.
  Blocking lets the layers above **coalesce** queued work (and, in
  the extreme, drop back to a resync) rather than building an
  unbounded backlog. The `EventSequencer`'s coalescing (below) is
  one half of this; the dataplane's batched `apply()` is the other.
- **Local filtering.** Only ~100 local WEPs need their policy
  computed on a given node, not the 100k in the cluster. The graph
  filters cluster-wide state down to the locally-relevant subset as
  early as possible (the `localEndpointDispatcher`, below).

### The four problems it owns

Centralising this logic in one place keeps every dataplane
implementation simpler. The calc graph is the single place that
deals with:

1. **Out-of-order / cross-resource inconsistency.** The syncer API
   is eventually consistent, so a resource can reference another
   that the graph hasn't heard about yet (a WEP naming a profile
   that doesn't exist; a rule selecting a not-yet-known label).
2. **Transient duplicate state.** Add/delete reordering can
   briefly present two WEPs with the same IP. The graph detects the
   conflict and decides how to resolve it, so the dataplane never
   has to.
3. **Local relevance filtering.** Reducing cluster state to this
   node's dataplane state (problem (c) above).
4. **Dataplane-friendly output ordering.** Dependencies are always
   emitted *before* the resources that depend on them, and are only
   removed once nothing depends on them any more. This is the
   `EventSequencer`'s job (below) and is the contract the dataplane
   relies on.

### Review notes for this section

- Wholesale recomputation from cached state (recompute the output
  from scratch, then dedup no-op changes downstream) is the
  *simplest* option and is perfectly fine wherever the recomputed
  set is small or low-churn — re-sorting one local endpoint's policy
  list, or recomputing Felix configuration from the handful of
  config resources, are both legitimate. Use it wherever it's the
  right trade-off; reach for fine-grained incremental updates only
  when full recomputation would be too expensive.
- The actual anti-pattern is per-update work whose cost scales with
  the *cluster-wide* resource count on a *high-churn* path — e.g.
  touching all 100k endpoints every time any one of them changes.
  That is a scaling regression and needs an explicit justification
  or a redesign.

## The node model and the node contract

Calculation nodes are **plain function objects wired into a call
graph**, not goroutines. An update entering the graph propagates
synchronously through the nodes via direct method calls
(`OnUpdate`, registered callbacks) and the call returns when
propagation is complete. There is no concurrency between nodes, so
nodes need no locking. (Hidden internal parallelism inside a single
node is *conceivable* if it earned its keep, but the bar is high
and it must remain an invisible implementation detail behind the
synchronous API.)

Every node must honour the following contract.

### Handle add, update and delete — in any order

The syncer can deliver KVs in any order and can coalesce them
(below). A node must react correctly to a create, an update, or a
delete for any resource it tracks, arriving at any time.

### Handle inconsistency, and the consistent→inconsistent transition

A node must cope with referential inconsistency — a WEP that names a
non-existent profile, a rule selecting an unknown endpoint — and
produce *some* well-defined output for it.

The subtle, load-bearing half of this: a node must handle the
transition **from consistent to inconsistent** and end up in
exactly the same state as if the inconsistency had been present
from start of day. If resource B disappears while A still
references it, the node must reconcile to the "B is missing"
output — it must **not** cling to the last-known-good value of B.

### Be memoryless

This is the single most important node invariant. **A node's output
must depend only on the current set of datastore resources, never
on history.** Do not buffer "the last good output" to paper over a
transient inconsistency.

Buffering history is forbidden because:

- It makes testing exponentially harder — output now depends on the
  path taken, not just the destination, so the state space the
  tests must cover explodes.
- It defers the visible impact of a bug. A node that hoards stale
  state can look correct for weeks and then emit the wrong thing
  only after a Felix restart drops the hoarded state — by which
  time all the logs and context that would explain it are gone.

Buffering for **work-avoidance** is a different thing and is
allowed (see no-op suppression below, and the `EventSequencer`):
that kind of buffer changes *when* and *how efficiently* output is
produced, never *what* the output is for a given datastore state.

### Suppress no-op churn where it matters

A node should suppress emitting a downstream update when nothing it
cares about actually changed — but only where it matters, i.e.
where the downstream would otherwise do significant redundant work.
The canonical example (since fixed): WEP↔policy match changes used
to re-trigger sorting the policy list for the affected endpoint. At
start of day with 100 local WEPs and 200 policies each, the naive
version sorted 200 × 100 = 20,000 times instead of once per WEP =
100 times. Suppression here was worth it; suppression on a leaf
that does no downstream work is not worth the complexity.

### Edge-triggered indexing must pair add/remove with identical keys

Where a node maintains reference counts or membership indexes (the
label indexes are the prime example, below), the add and remove
operations are **edge-triggered** and must be keyed **identically**.
An add keyed one way and a remove keyed even slightly differently
leaks the entry, and at scale that leak is a real, observed bug
class — not a theoretical one.

### Review notes for this section

- **Reject added buffering of "good" output.** If a change makes a
  node remember a previous output to survive an inconsistency, that
  is the most common way these changes go wrong (see Common failure
  modes). Push back unless the buffer is purely for work-avoidance
  and the *content* of the output is still a pure function of
  current state.
- A new index or refcount needs its add/remove keying checked for
  exact symmetry, and needs calc-graph FV coverage that exercises
  the teardown direction, not just the build-up direction.
- A node added as a goroutine, or that takes a lock, is almost
  certainly wrong for this codebase — flag it and ask why the
  synchronous model doesn't fit.

## The upstream (syncer) contract

The syncer delivers an **eventually-consistent sequence of KV
events**. A node should reason about each event in isolation,
against its own previous knowledge of that one resource — not about
the sequence as a whole.

- **`nil` value** means the resource does not exist: either it was
  deleted, or it failed validation and must be treated as
  non-existent. (Validation lives upstream in
  `calc/validation_filter.go` — `ValidationFilter` nils out invalid
  values rather than altering them — so by the time a non-nil value
  reaches a node it has passed schema/semantic validation.)
- **Non-nil value** means "this is the resource's current state;
  update yourself to match." The node compares against whatever it
  held before and reconciles.
- **Coalescing.** The syncer may collapse a run of updates to the
  same resource — `update → update → delete → update → update` can
  arrive as just the final `update`. A node must never assume it
  sees every intermediate state.
- **Reversion is possible.** A datastore resync that lands on a
  node with a stale cache can legitimately move a resource
  *backwards* to an earlier version. "Compare current event against
  my state and reconcile" handles this for free; "assume values
  only move forward" does not.

### The update-type side channel

Each event carries an update type — `Update.UpdateType`, of type
`api.UpdateType` (`UpdateTypeKVNew` / `UpdateTypeKVUpdated` /
`UpdateTypeKVDeleted` / `UpdateTypeKVUnknown` in
`libcalico-go/lib/backend/api`). It is a **side channel** describing
what *kind* of upstream event produced this delivery (with defined
rules for recomputing it when events coalesce). Its original purpose
was to allow stats to be kept without retaining every object —
increment a counter on a create, decrement on a delete, ignore
updates (see `calc/stats_collector.go`). Treat it as advisory
metadata about the delivery, **not** as the source of truth for
whether the resource exists: that is the value being nil or non-nil.
A node whose *correctness* depends on the update type is usually
relying on it wrongly.

### Review notes for this section

- A node that branches on the update type to decide whether a
  resource exists (rather than on nil/non-nil) is suspect. Stats
  and similar bookkeeping are the legitimate uses.
- A node that assumes monotonic resource versions, or that it will
  observe every intermediate update, is wrong — coalescing and
  reversion both break those assumptions.

## Wiring and inter-node ordering

The graph is assembled in `calc/calc_graph.go` (`NewCalculationGraph`).
Updates enter through the `AllUpdDispatcher` (`dispatcher.Dispatcher`),
which fans each KV out by resource type to the nodes registered for
it. A second dispatcher, the `localEndpointDispatcher`, carries the
**locally-filtered** endpoint stream — an `endpointHostnameFilter`
(in the `calc` package) is registered first on it and forwards only
endpoints hosted on this node, which is where the cluster→local
reduction (problem (c)) happens. (The dispatcher itself is
hostname-agnostic; the filter does the reduction.)

Most wiring order is irrelevant because nodes are independent. The
order that *does* matter follows one pattern: **a node that consumes
"A matches B" events generally wants to have already heard about A
and B individually before it hears that they match.** Otherwise it
has to buffer the match until A and B turn up.

The one concrete load-bearing ordering in `NewCalculationGraph` is
about **handler registration order on the same dispatcher**, not
about the order the dispatchers are created (`dispatcher.Register`
appends per key-type and `OnUpdate` then iterates handlers in
registration order):

- The `LiveMigrationCalculator` (`calc/live_migration_calculator.go`)
  has its `OnUpdate` registered on the `localEndpointDispatcher`
  **before** the `ActiveRulesCalculator` registers with that same
  dispatcher, so the ARC sees migration-adjusted endpoint state.
  This is the only such constraint the code calls out in a comment.

If you genuinely must consume a "matches" event before the
endpoints it references, you may rely on hearing about the
endpoints **in the same calc-graph loop** as the match event, so
the buffer you need is small and short-lived. And remember the
symmetric teardown: if you heard A and B before "A matches B", then
on deletion you will hear A and B removed *first*, then "A no longer
matches B".

### The principal nodes

| Node (file) | Role |
|---|---|
| `ValidationFilter` (`validation_filter.go`) | Nils out invalid resources (treat-as-missing) before they reach the graph |
| `AllUpdDispatcher` / `localEndpointDispatcher` (`dispatcher` pkg) + `endpointHostnameFilter` (`calc` pkg) | Type-based fan-out; the filter does the local-endpoint reduction |
| `LiveMigrationCalculator` (`live_migration_calculator.go`) | Adjusts endpoint state for KubeVirt-style live migration |
| `ActiveRulesCalculator` (`active_rules_calculator.go`) | Tracks which policies/profiles are active given local endpoint labels |
| `RuleScanner` (`rule_scanner.go`) | Extracts selector/named-port references from active rules; drives the label index |
| `PolicyResolver` / `PolicySorter` (`policy_resolver.go`, `policy_sorter.go`) | Computes the ordered per-endpoint policy list (tiers, order) |
| `L3RouteResolver` (`l3_route_resolver.go`) | Computes a generalized route map of Calico-known IP space from IP pools, WEPs, host IPs. Generalized in the sense that some entries are just "we know this useful information about this CIDR" rather than actual IP routes. |
| `VXLANResolver` (`vxlan_resolver.go`) | Computes VTEP entries |
| `EncapsulationResolver` (`encapsulation_resolver.go`) | Derives encap mode from IP-pool config |
| `IstioCalculator` (`istio_calculator.go`) | Marks WEPs in the Istio ambient mesh |
| `EventSequencer` (`event_sequencer.go`) | Output stage: buffers, coalesces, flushes in dependency order |

### Review notes for this section

- A PR that adds a consumer of "A matches B"-style events should
  state where it sits relative to the producers of A and B, and
  confirm it handles the teardown order (A/B removed before the
  un-match). If it buffers, the buffer must rely only on
  same-loop delivery, not on cross-loop retention.
- A PR that reorders node registration must justify it against the
  "matches after members" pattern; most reorderings are inert, but
  the one that isn't — `LiveMigrationCalculator`'s `OnUpdate`
  registered on `localEndpointDispatcher` before the ARC's — is
  silently load-bearing.

## Label indexes and refcounting

[`felix/labelindex/`](../labelindex/) holds the graph's most
intricate machinery: `InheritIndex` (label inheritance from
profiles/namespaces down to endpoints) and
`SelectorAndNamedPortIndex` (which selectors match which endpoints,
expanded to IP-set membership). These are where reference-counting
bugs and leaks tend to live.

Two things make them hard, and both are deliberate:

- **Edge-triggered, identically-keyed add/remove** (see the node
  contract). Every membership add must be balanced by exactly one
  remove using the same key. A keying mismatch leaks.
- **Rare-but-common-at-scale corner cases.** The classic is **two
  WEPs transiently sharing one IP** due to add/delete reordering. At
  100k endpoints with churn, "rare per endpoint" becomes "happening
  somewhere all the time," so these paths must be correct, not
  merely improbable-and-ignored. The index code carries deliberately
  adversarial tests aimed at these cases: the shared-IP / overlapping
  membership cases live in `labelindex/named_port_index_test.go`
  ("two endpoints overlapping IPs") and the FV base states, while
  `labelindex/dedup_overlap_repro_test.go` covers the related
  CIDR-containment dedup sub-case.

These packages are **part of the calc graph** for the purposes of
the testing rule below, even though they live in their own
directory: changes to them belong in the calc-graph FV suite.

### Review notes for this section

- Any change to membership bookkeeping must preserve exact
  add/remove key symmetry. Audit both directions.
- Any change must keep the shared-IP / overlapping-membership
  corner cases working, and must extend the adversarial index tests
  rather than only adding happy-path coverage.

## The EventSequencer (output stage)

`EventSequencer` (`calc/event_sequencer.go`) is the graph's output
boundary. It buffers updates in `pending*` maps/sets and emits them
only when `Flush()` is called, coalescing repeated changes to the
same object in between.

### Coalescing is back-pressure, not an optimisation

Coalescing is half of the system's back-pressure mechanism. When
the dataplane stalls for a second or more on a big update while the
datastore is churning hard, buffering-with-coalescing in the
sequencer **bounds memory** (you hold at most one pending entry per
resource, so the bound is ~the number of resources in the cluster)
and **bounds the size of the update** eventually handed to the
dataplane. The worst case degrades gracefully: the dataplane enters
a catch-up loop where each pass takes N seconds and absorbs the
previous N seconds of churn, rather than growing an unbounded queue.

### Flush order is the dependency contract

`Flush()` emits in a strict, commented order so that the dataplane
**never sees a reference before its referent, and never loses a
referent while something still references it.** The shape is:

1. Ready flag, then config, first (a config change may restart Felix).
2. Additions in dependency order: **IP sets → policies → profiles →
   endpoints**. A referent is always in place before the thing that
   refers to it.
3. Removals in the **reverse** order: endpoints → profiles →
   policies → IP sets. Nothing is removed while a live consumer
   still points at it.
4. VXLAN ordered so a route never exists without its VTEP: **VTEP
   adds before route adds; route removes before VTEP removes**
   (route removes also precede route adds, to minimise peak
   occupancy).
5. Rarer cluster-wide updates (hosts, IP pools, wireguard, encap,
   BGP config, services) where ordering is looser.

This ordering is **the contract the dataplane assumes** (see
[`dataplane.md` → The dataplane API](./dataplane.md#the-dataplane-api-calc-graph--dataplane-contract)).
The dataplane is entitled to assume references arrive before
referents — policies before endpoints, IP sets before policies,
profiles before referencing endpoints.

### Adding a new message type: where does it slot?

The decision procedure for a new output message:

1. Identify its dependencies (what must already be in the dataplane
   before this message is safe to apply) and its dependents (what
   must still be present when this message is removed).
2. Place its **add** after its dependencies' adds; place its
   **remove** before its dependencies' removes (i.e. mirror it).
3. If it has no dependency relationship, it can join the loosely-
   ordered tail.

### The missing-resource tension

Strict ordering collides with referential inconsistency: what does
the graph emit when a referent is genuinely missing (not just late)?
There are three sanctioned strategies; which one fits depends on the
trade-off between how much work it is to handle the case in the
dataplane versus buffering it in the graph, and on what actually
makes sense for the particular resource type:

- **(a) Synthesize a safe stand-in.** Good when a safe default
  exists. Felix does this for profile rules: a missing profile is
  resolved to a fail-safe **deny-all** rule set (the `DummyDropRules`
  in `calc/active_rules_calculator.go`), so policy still resolves and
  fails closed. (A stand-in doesn't always make sense — for some
  resource types there is no meaningful dummy value.)
- **(b) Buffer the dependent until the dependency arrives.** Often
  the **wrong** choice. You must **not** buffer endpoints or
  policies — they are security-critical, most dependency chains
  start at endpoints, and delaying them risks leaving endpoints with
  stale policy/configuration, which could be a security hole.
  Reserve buffering for non-security-critical leaves.
- **(c) Make an explicit exception and handle it in the dataplane.**
  Pass the inconsistency through to the dataplane as a signal rather
  than resolving it in the graph, letting the dataplane fail closed
  on its own terms. The right choice when the dataplane has to do
  something for this case anyway — e.g. a WEP gains a new
  security-critical field, so a missing dependency means *that
  endpoint* must fail closed, and neither buffering nor a dummy
  resource fits.

The hard invariant under all three: a missing dependency must never
silently leave a security-critical resource (an endpoint or policy)
open — it has to **fail closed**, via whichever of (a)/(c) suits the
resource. Which mechanism, and how much of the work lands in the
graph versus the dataplane, is the judgement call; failing closed is
not.

### Review notes for this section

- A new emitted message type must document, in the PR, its place in
  the flush order and why (dependencies before it, dependents after
  it). A message added to the wrong phase produces
  reference-before-referent bugs that only bite under specific
  orderings — exactly what FV expansion is designed to catch, so it
  needs FV coverage.
- A change that handles a missing referent by buffering an endpoint
  or a policy is almost always wrong. Prefer (a) a fail-closed
  stand-in (`DummyDropRules`-style) or (c) a pass-through signal.
- A change that removes or weakens a coalescing path needs to argue
  it doesn't break the memory/size bound the back-pressure design
  relies on.

## In-sync semantics

The graph forwards the datastore's `InSync` signal downstream. Its
significance is almost entirely a **dataplane** concern — the
dataplane defers all kernel mutation, and especially the cleanup of
stale state left by a previous Felix, until the first post-`InSync`
apply. The full rationale lives in
[`dataplane.md` → Restart, resync and mark-and-sweep](./dataplane.md#restart-resync-and-mark-and-sweep).

The calc-graph-side rule is simply: **do not fabricate or withhold
the in-sync signal.** Emitting derived state and marking in-sync
before the datastore truly is in sync would let the dataplane sweep
away state it just hasn't been told about yet.

## Testing: the calc-graph FV framework

Calc-graph changes — **including** changes to `labelindex` and the
other helper packages — must come with tests in the **calc-graph FV
suite** (`calc/calc_graph_fv_test.go`, with states defined in
`calc/states_for_test.go`). Despite the "FV" name these are 100%
pure unit tests; "FV" refers to the fact that they exercise the
*whole assembled graph* end to end (datastore KVs in, dataplane
messages out) rather than one node in isolation.

This is strongly preferred over per-node unit tests because the
harness **expands every test you write for free**, and because an
input-state→output-state suite is extremely robust to later
refactoring — it only cares about what goes in and what comes out,
not how the graph is wired internally.

For a test expressed as a sequence of datastore states, the harness
(`testExpanders()` in `calc/calc_graph_fv_test.go`) generates a
family of companion runs — five expanders beyond the identity run,
all applied unless `DISABLE_TEST_EXPANSION=true`:

- **(a) `reverseKVOrder`** — reverse the KV order within each state;
  checks the output doesn't depend on intra-state delivery order.
- **(b) `reverseStateOrder`** — reverse the order of the states;
  checks the build-up and teardown directions both work.
- **(c) `insertEmpties`** — insert an empty state between each pair
  of states; forces everything to be created, fully torn down, then
  recreated, over and over.
- **(d) `splitStates`** — run each state standalone (from empty),
  checking each state is self-consistent in isolation.
- **(e) `squashStates`** — collapse the whole sequence (including
  deletions) into a single state via `KVDeltas`, checking the graph
  reaches the same end state in one step as it does incrementally.

### Blind spots to cover with targeted states

The expansions are powerful but not total. Watch for:

- **Symmetric sequences test only one direction.** A sequence like
  `[{A}, {A,B}, {A}]` is its own reverse, so it only ever exercises
  "A created before B" — never "B before A", and never the
  `{A,B} → {B}` transition (A deleted *while B still references it*).
  If the teardown-with-live-referrer case matters (it usually does
  for indexes and refcounts), add an explicit asymmetric state
  sequence for it.

### Review notes for this section

- A calc-graph (or labelindex) change without a calc-graph FV state
  is the exception, not the norm, and needs explicit justification.
  A pile of per-node unit tests is **not** a substitute — funnel
  the coverage through the FV framework so it gets the free
  expansions and survives refactoring.
- Check the new states aren't accidentally symmetric (the
  `[{A},{A,B},{A}]` trap). If they are, the teardown-with-live-
  referrer path is untested — add an asymmetric sequence.

## Common failure modes

The recurring ways calc-graph changes (from humans and AIs alike)
go wrong:

1. **Buffering "good" output across an inconsistency.** Adding
   memory of the last-known-good value so the output "stays nice"
   when the datastore goes inconsistent. This violates the
   memoryless invariant. The graph must always *sequence* output
   nicely, but the *content* must be a pure function of current
   state. If a resource is broken, emit something (a fail-closed
   stand-in or a pass-through signal) — never withhold a
   security-critical update.
2. **Buffering security-critical resources.** Even where buffering a
   dependent is tempting, endpoints and policies must never be held
   back. Fail closed instead.
3. **Recomputing too much per update.** Work proportional to
   cluster-wide resource counts instead of local counts — a scaling
   regression. (The historical 20,000-sorts bug.)
4. **Leaky / asymmetric refcounting.** Add and remove keyed
   differently in an index, leaking entries at scale.
5. **Skipping the FV suite.** Heavy per-node unit tests, no
   calc-graph FV state — so the orderings and teardown paths the
   expansions would have caught go untested.

## Keep this document in sync with the code

The repo-wide doc-update rule
([`.claude/CLAUDE.md` → Documentation map](../../.claude/CLAUDE.md),
mirrored in
[`.github/copilot-instructions.md`](../../.github/copilot-instructions.md))
applies. For the calc graph, "changes how it works" means: a new
calculation node or a change to how nodes are wired; a new emitted
message type or a change to the `EventSequencer` flush order; a
change to a label index or other refcounting structure; a change to
how the graph treats inconsistency, in-sync, or the upstream
contract. Update the relevant section of this file in the same PR,
and update
[`dataplane.md` → The dataplane API](./dataplane.md#the-dataplane-api-calc-graph--dataplane-contract)
as well if the output contract changes. This file is the source of
truth for the calc graph's invariants.
