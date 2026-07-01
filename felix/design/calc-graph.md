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

Design doc for Felix's calculation graph: the code under
[`felix/calc/`](../calc/) plus the indexing packages it depends on,
[`felix/labelindex/`](../labelindex/) and
[`felix/dispatcher/`](../dispatcher/). Read it before editing those
packages or reviewing a PR that touches them.

The output boundary — the protobuf messages the graph emits to the
dataplane — is the other end of the contract documented in
[`dataplane.md` → The dataplane API](./dataplane.md#the-dataplane-api-calc-graph--dataplane-contract).
Build/test commands are in [`felix/CLAUDE.md`](../CLAUDE.md); the
whole-Felix overview is in [`felix/DESIGN.md`](../DESIGN.md).

## Conventions

- "WEP"/"HEP" = workload/host endpoint. "Local" = hosted on this
  node.
- "Node" unqualified means a **calculation node** (a vertex in the
  graph), not a Kubernetes node.
- A "KV" is a datastore key/value pair from the syncer: a typed key
  plus a value that is either `nil` (gone/invalid) or the resource's
  current state.
- Paths are repo-relative; type/function/field names are cited, line
  numbers omitted.

## What the calc graph is for

The calc graph consumes the eventually-consistent stream of
datastore updates from the syncer and emits protobuf messages
describing the desired state of *this node's* dataplane in
Calico-internal terms (local WEPs, resolved policy rules,
fully-expanded IP sets, routes, VTEPs). Its output is a function of
current datastore state, computed incrementally so it can keep up
with churn.

It was built for **100k endpoints, ~2k policies, ~1000
endpoint-updates/second**, with the dataplane applying the result
sub-second. That drives three properties:

- **Incremental, minimal-delta output** so the dataplane applies the
  smallest possible change set with low latency.
- **Back-pressure.** If the graph or dataplane can't keep up,
  upstream layers block; blocking lets them coalesce queued work
  (see the `EventSequencer`) instead of growing an unbounded backlog.
- **Local filtering.** Only ~100 local WEPs need policy computed, not
  the 100k in the cluster, so the graph reduces cluster state to the
  local subset early (the `localEndpointDispatcher`, below).

Centralising this keeps every dataplane simpler. The graph is the
single place that handles:

1. **Cross-resource inconsistency** from eventual consistency — a WEP
   naming a not-yet-known profile, a rule selecting an unknown label.
2. **Transient duplicate state** — e.g. two WEPs briefly sharing an
   IP after add/delete reordering; the graph resolves the conflict so
   no dataplane has to.
3. **Local relevance filtering** (problem above).
4. **Dataplane-friendly output ordering** — dependencies emitted
   before their dependents and removed only once nothing needs them
   (the `EventSequencer`'s job).

### Review notes

- Recomputing output wholesale from cached state (then dedup'ing
  no-op changes downstream) is the simplest approach and is fine
  wherever the recomputed set is small or low-churn — re-sorting one
  endpoint's policy list, or recomputing Felix config from the
  handful of config resources. Use it where it's the right
  trade-off; reach for fine-grained incremental updates only when
  full recomputation is too expensive.
- The anti-pattern is per-update work that scales with the
  *cluster-wide* resource count on a *high-churn* path (e.g. touching
  all 100k endpoints when one changes). That needs justification or a
  redesign.

## The node contract

The graph is a DAG of nodes, but the edges are **direct function
calls, not goroutines or channels**: an update propagates
synchronously through `OnUpdate`/callback calls and the call returns
once propagation is complete. There is no concurrency between nodes
and therefore no locking. (New folks sometimes read "calc *graph*"
and picture goroutines and channels — it isn't that.)

Every node must:

**Handle add, update and delete for any resource it tracks,** and
handle **referential inconsistency** — a WEP naming a missing
profile, a rule selecting an unknown endpoint — by producing some
well-defined output. This includes the consistent→inconsistent
transition: if resource B disappears while A still references it, the
node must reconcile to the "B is missing" output, not cling to B's
last-known value.

**Depend only on current state, not on history** (no hysteresis).
Don't buffer "the last good output" to paper over a transient
inconsistency. History-dependent output makes testing explode (the
result depends on the path, not just the destination) and defers the
visible impact of a bug — a node hoarding stale state can look
correct for weeks, then emit the wrong thing only after a restart
drops the hoard, long after the logs that would explain it are gone.
(Buffering purely for *work-avoidance* is fine — it changes when and
how efficiently output is produced, not what it is; see no-op
suppression.)

**Suppress no-op churn where it matters** — where a downstream would
otherwise do significant redundant work. The canonical case (since
fixed): WEP↔policy match changes used to re-sort each endpoint's
policy list; at start of day with 100 local WEPs × 200 policies that
sorted 20,000 times instead of 100. Suppression on a leaf that does
no downstream work isn't worth the complexity.

**Balance index add/remove exactly.** Where a node keeps reference
counts or membership indexes (the label indexes, below), every add
must be matched by exactly one remove keyed *identically*. A keying
mismatch leaks entries — a real, observed bug class at scale, not a
theoretical one.

### Review notes

- Reject added buffering of "good" output to survive an
  inconsistency — the most common way these changes go wrong. Allow a
  buffer only if it's purely for work-avoidance and the output
  *content* is still a function of current state.
- A new index or refcount needs its add/remove keying checked for
  symmetry, with FV coverage of the teardown direction, not just
  build-up.
- A node that spawns a goroutine or takes a lock is almost certainly
  wrong here — ask why the synchronous model doesn't fit.

## The upstream (syncer) contract

The syncer delivers an eventually-consistent sequence of KV events.
Reason about each event on its own, against your prior knowledge of
*that one resource* — not about the sequence as a whole.

- **`nil` value** = the resource doesn't exist (deleted, or failed
  validation and treated as absent). Validation is upstream in
  `calc/validation_filter.go` (`ValidationFilter` nils out invalid
  values rather than altering them), so a non-nil value has already
  passed schema/semantic validation.
- **Non-nil value** = the resource's current state; compare against
  what you held and reconcile.

The **only** real guarantee is eventual convergence to the latest
value (supported datastores make writes durable, so connectivity
permitting you will eventually see it). Everything else is fair
game. For a resource that truly went `Created → A → B → C`, a node
might observe any of:

- `A → B → C`
- `A → C` — `B` coalesced away
- `C` — `A` and `B` coalesced away
- `A → C → B → C` — reached `C`, then a resync hit a stale replica
  (back to `B`), then caught up
- `C → Deleted → A → B → C` — resync hit a replica so stale the
  resource didn't exist there yet, giving a **spurious `Deleted`**

So a node must not assume ordering, monotonic versions, that it sees
every transition, or even that a `Deleted` is real and final —
"compare the event against my state and reconcile" handles all of
these; "assume values only move forward" does not.

### The update-type side channel

Each event also carries `Update.UpdateType` (`api.UpdateType`:
`UpdateTypeKVNew`/`KVUpdated`/`KVDeleted`/`KVUnknown` in
`libcalico-go/lib/backend/api`) — a side channel describing what kind
of upstream event produced this delivery, recomputed when events
coalesce. Its original purpose was stats without retaining objects
(increment on create, decrement on delete; see
`calc/stats_collector.go`). Treat it as advisory: whether the
resource exists is the value being nil or non-nil, not the update
type.

### Review notes

- A node that decides *existence* from the update type rather than
  nil/non-nil is suspect; stats-style bookkeeping is the legitimate
  use.
- A node that assumes monotonic versions or that it sees every
  intermediate update is wrong — coalescing and reversion break both.

## Wiring and inter-node ordering

The graph is assembled in `calc/calc_graph.go`
(`NewCalculationGraph`). Updates enter via the `AllUpdDispatcher`
(`dispatcher.Dispatcher`), which fans each KV out by resource type.
A second dispatcher, the `localEndpointDispatcher`, carries the
locally-filtered endpoint stream: an `endpointHostnameFilter` (in the
`calc` package) registered first on it forwards only endpoints on
this node — that's where the cluster→local reduction happens (the
dispatcher itself is hostname-agnostic).

Most wiring order is irrelevant because nodes are independent. The
pattern that matters: **a node consuming "A matches B" events usually
wants to hear about A and B individually first**, or it has to buffer
the match until they arrive. The one load-bearing case is handler
registration order *on the same dispatcher* (`dispatcher.Register`
appends, and `OnUpdate` iterates in registration order):

- `LiveMigrationCalculator` (`live_migration_calculator.go`)
  registers its `OnUpdate` on the `localEndpointDispatcher` **before**
  `ActiveRulesCalculator` does. This ensures the LMC sees WEP updates
  first, so its `wepData` is populated when the ARC fires computed
  selector-match callbacks. (The code comments this constraint.)

If you must consume a "matches" event before the endpoints it
references, you can rely on hearing about the endpoints **in the same
calc-graph loop**, so the buffer stays small. Note the symmetric
teardown: having heard A and B before "A matches B", on deletion you
hear A and B removed *first*, then "A no longer matches B".

A rendered overview of the node graph is kept by hand in
[`felix/docs/calc.dot`](../docs/calc.dot) (rendered via the
`felix/Makefile`); update it when you add or rewire a node.

### The principal nodes

Descriptions track each node's godoc — see the source for detail.

| Node (file) | Role |
|---|---|
| `ValidationFilter` (`validation_filter.go`) | Nils out invalid resources (treat-as-missing) before they reach the graph |
| `AllUpdDispatcher` / `localEndpointDispatcher` (`dispatcher` pkg) + `endpointHostnameFilter` (`calc` pkg) | Type-based fan-out; the filter does the local-endpoint reduction |
| `LiveMigrationCalculator` (`live_migration_calculator.go`) | Correlates local WEPs with LiveMigration resources to set the `live_migration_role` field on emitted `proto.WorkloadEndpoint`s (OpenStack and KubeVirt live migration) |
| `ActiveRulesCalculator` (`active_rules_calculator.go`) | Given local endpoints, emits which policies/profiles are active (matching on each policy's own selector; rule selectors are handled by the `RuleScanner`) |
| `RuleScanner` (`rule_scanner.go`) | Scans active rules for selectors/tags, tracks which are active, and converts `model.Rule` to `ParsedRule` (selectors/tags → IP sets). Endpoint matching itself is done downstream by a `labelindex.InheritIndex` |
| `PolicyResolver` / `PolicySorter` (`policy_resolver.go`, `policy_sorter.go`) | Marries active policies with local endpoints (told which match by the ARC) to emit the complete, ordered per-endpoint policy set (tiers, order) |
| `L3RouteResolver` (`l3_route_resolver.go`) | Indexes IPAM blocks, IP pools and node metadata into longest-prefix-match routes over Calico-known IP space (CIDR + pool type/metadata + is-host + owning host for workloads); consumed by the BPF and VXLAN dataplanes |
| `VXLANResolver` (`vxlan_resolver.go`) | Resolves node IP/config into a VTEP per host (`proto.VXLANTunnelEndpointUpdate`/`Remove`); the dataplane only programs VXLAN routes once the VTEP is ready |
| `EncapsulationResolver` (`encapsulation_resolver.go`) | Derives encap mode from IP-pool config (restarts Felix if it changed) |
| `IstioCalculator` (`istio_calculator.go`) | Marks local WEPs that are in the Istio ambient mesh so downstream can apply mesh networking |
| `EventSequencer` (`event_sequencer.go`) | Output stage: buffers, coalesces, flushes in dependency order |

### Review notes

- A PR adding a consumer of "A matches B" events should state where it
  sits relative to the producers of A and B, and handle the teardown
  order. Any buffer must rely only on same-loop delivery.
- A PR reordering node registration must justify it against the
  matches-after-members pattern; most reorderings are inert, but the
  `LiveMigrationCalculator`-before-ARC one is silently load-bearing.

## Label indexes and refcounting

[`felix/labelindex/`](../labelindex/) is the graph's most intricate
code: `InheritIndex` (label inheritance from profiles/namespaces down
to endpoints) and `SelectorAndNamedPortIndex` (which selectors match
which endpoints, expanded to IP-set membership). Reference-counting
bugs live here. Two things make it hard:

- **Balanced, identically-keyed add/remove** (see the node contract):
  one remove per add, same key, or it leaks.
- **Corner cases that are rare per-endpoint but common at scale** —
  the classic being two WEPs transiently sharing one IP. At 100k
  endpoints with churn these happen constantly, so they must be
  correct, not ignored. The adversarial tests target exactly these:
  shared-IP/overlapping membership in
  `labelindex/named_port_index_test.go` and the FV base states;
  `labelindex/dedup_overlap_repro_test.go` covers the related
  CIDR-containment dedup case.

These packages are part of the calc graph for the testing rule
below, despite living in their own directory.

### Review notes

- Preserve exact add/remove key symmetry; audit both directions.
- Keep the shared-IP/overlapping-membership cases working, and extend
  the adversarial index tests rather than only adding happy-path
  coverage.

## The EventSequencer (output stage)

`EventSequencer` (`calc/event_sequencer.go`) is the output boundary.
It buffers updates in `pending*` maps/sets and emits them on
`Flush()`, coalescing repeated changes to the same object in between.

### Coalescing is back-pressure

Coalescing is half the back-pressure mechanism. When the dataplane
stalls on a big update while the datastore churns, coalescing
**bounds memory** (at most one pending entry per resource, so ~the
cluster's resource count) and **bounds the update size** handed to
the dataplane. Worst case degrades gracefully: the dataplane runs a
catch-up loop, each pass absorbing the previous pass's churn, rather
than growing an unbounded queue.

### Flush order is the dependency contract

`Flush()` emits in a strict, commented order so the dataplane never
sees a reference before its referent, nor loses a referent while
something still references it:

1. Ready flag, then config (a config change may restart Felix).
2. Additions in dependency order: **IP sets → policies → profiles →
   endpoints**.
3. Removals in **reverse**: endpoints → profiles → policies → IP
   sets.
4. VXLAN so a route never exists without its VTEP: VTEP adds before
   route adds; route removes before VTEP removes (route removes also
   precede route adds, to minimise peak occupancy).
5. Rarer cluster-wide updates (hosts, IP pools, wireguard, encap, BGP
   config, services), looser ordering.

This is **the contract the dataplane assumes** (see
[`dataplane.md` → The dataplane API](./dataplane.md#the-dataplane-api-calc-graph--dataplane-contract)):
references arrive before referents — IP sets before policies,
policies/profiles before referencing endpoints.

To slot in a new message type: identify its dependencies (must be in
the dataplane before it) and dependents (must still be present when
it's removed); place its add after its dependencies' adds and its
remove before theirs; if it has no dependencies, join the loose tail.

### The missing-resource tension

When a referent is genuinely missing (not just late), there are
three sanctioned strategies. Which fits depends on the cost of
handling it in the dataplane versus buffering in the graph, and on
what makes sense for the resource type:

- **(a) Synthesize a safe stand-in.** Felix does this for profile
  rules: a missing profile resolves to a fail-safe deny-all rule set
  (`DummyDropRules` in `calc/active_rules_calculator.go`). Some
  resource types have no meaningful stand-in.
- **(b) Buffer the dependent until the dependency arrives.** Usually
  wrong. Never buffer endpoints or policies: they're
  security-critical, most dependency chains start at endpoints, and
  delaying them risks leaving endpoints with stale
  policy/configuration — a security hole. Reserve buffering for
  non-security-critical leaves.
- **(c) Pass the inconsistency through to the dataplane** as a signal
  and let it fail closed on its own terms. The right choice when the
  dataplane must act anyway — e.g. a WEP gains a security-critical
  field, so a missing dependency means *that endpoint* must fail
  closed and neither buffering nor a dummy fits.

The invariant across all three: a missing dependency must never
silently leave an endpoint or policy *open* — it must fail closed,
via whichever of (a)/(c) suits. The mechanism is a judgement call;
failing closed is not.

### Review notes

- A new message type must document its place in the flush order (and
  why) and carry FV coverage — wrong-phase bugs only bite under
  specific orderings, which FV expansion is built to catch.
- Handling a missing referent by buffering an endpoint or policy is
  almost always wrong; prefer (a) or (c).
- Removing or weakening a coalescing path must argue it doesn't break
  the memory/size bound back-pressure relies on.

## In-sync semantics

The graph forwards the datastore's `InSync` signal downstream. Its
significance is a dataplane concern: the dataplane defers all kernel
mutation — especially cleanup of stale state from a previous Felix —
until the first post-`InSync` apply (see
[`dataplane.md` → Restart, resync and mark-and-sweep](./dataplane.md#restart-resync-and-mark-and-sweep)).
The calc-graph rule: **don't fabricate or withhold `InSync`.**
Signalling in-sync early would let the dataplane sweep state it just
hasn't been told about yet.

## Testing: the calc-graph FV framework

Calc-graph changes — including changes to `labelindex` and the other
helper packages — must come with tests in the calc-graph FV suite
(`calc/calc_graph_fv_test.go`; states in `calc/states_for_test.go`).
These are pure unit tests; "FV" reflects that they drive the *whole
assembled graph* end to end (datastore KVs in, dataplane messages
out) rather than one node in isolation. Prefer them to per-node unit
tests: the harness expands each test for free, and an
input-state→output-state suite survives refactoring.

From a sequence of datastore states, `testExpanders()` generates five
companion runs (unless `DISABLE_TEST_EXPANSION=true`):

- **`reverseKVOrder`** — reverse KV order within each state (output
  mustn't depend on intra-state delivery order).
- **`reverseStateOrder`** — reverse the states (tests build-up and
  teardown).
- **`insertEmpties`** — empty state between each pair (create, tear
  down, recreate).
- **`splitStates`** — each state standalone from empty
  (self-consistency in isolation).
- **`squashStates`** — collapse the whole sequence (incl. deletions)
  into one state via `KVDeltas` (same end state in one step as
  incrementally).

**Blind spot:** a symmetric sequence like `[{A}, {A,B}, {A}]` is its
own reverse, so it only ever tests "A before B" — never the
`{A,B} → {B}` transition (A deleted while B still references it). Add
an explicit asymmetric sequence when the teardown-with-live-referrer
case matters (it usually does for indexes/refcounts).

### Review notes

- A calc-graph (or labelindex) change without an FV state is the
  exception and needs justification; per-node unit tests aren't a
  substitute — funnel coverage through the FV framework.
- Check new states aren't accidentally symmetric (the
  `[{A},{A,B},{A}]` trap); if so, add an asymmetric sequence.

## Common failure modes

1. **Buffering "good" output across an inconsistency** — violates
   depend-only-on-current-state. Sequence output nicely, but its
   content must be a function of current state; if a resource is
   broken, emit a fail-closed stand-in or pass-through signal rather
   than withholding a security-critical update.
2. **Buffering security-critical resources** (endpoints, policies) —
   fail closed instead.
3. **Recomputing work that scales with cluster-wide counts on a
   high-churn path** (the historical 20,000-sorts bug).
4. **Leaky/asymmetric refcounting** — add and remove keyed
   differently.
5. **Skipping the FV suite** — so the orderings and teardown paths
   the expanders would catch go untested.

## Keep this document in sync with the code

The repo-wide doc-update rule
([`.claude/CLAUDE.md` → Documentation map](../../.claude/CLAUDE.md),
mirrored in
[`.github/copilot-instructions.md`](../../.github/copilot-instructions.md))
applies. For the calc graph, "changes how it works" means: a new node
or rewiring; a new emitted message type or a change to the
`EventSequencer` flush order; a change to a label index or other
refcounting structure; or a change to how the graph treats
inconsistency, in-sync, or the upstream contract. Update the relevant
section here, update the node graph in
[`felix/docs/calc.dot`](../docs/calc.dot) when nodes change, and
update
[`dataplane.md` → The dataplane API](./dataplane.md#the-dataplane-api-calc-graph--dataplane-contract)
if the output contract changes.
