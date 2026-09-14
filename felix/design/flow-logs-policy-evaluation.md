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

# Flow-log collector: pending-policy evaluation at scale — Design

Design doc for the user-mode policy evaluation that Felix's flow-log
collector runs to attribute pending (staged) policy verdicts to flows:
the evaluation paths in [`felix/collector/collector.go`](../collector/collector.go),
the engine they call in [`app-policy/checker/`](../../app-policy/checker/)
and its store in [`app-policy/policystore/`](../../app-policy/policystore/),
the fixtures and benchmarks in [`app-policy/policyscale/`](../../app-policy/policyscale/)
that define the performance target, and the changes planned to reach it.
Read it before editing any of those, or reviewing a PR that does. The
collector's data flow as a whole (readers, `epStats`, aggregation,
export) is the `flow-logs-collector` sub-design; this doc covers only
the policy-evaluation slice of it.

Tracking: CORE-13316.

## Conventions

- "The engine" is `checker.Evaluate` and the code under it; "the store"
  is a `policystore.PolicyStore`; "the collector" is the `collector`
  struct and its main `select` loop.
- "Verdict" and "trace" are the same thing: the `[]*calc.RuleID` the
  engine returns, the Pass entries on the way plus the final Allow or
  Deny. "Pending" means computed with `checker.StagedAsEnforced`: what
  the dataplane *would* do if staged policies were enforced.
- "Flow" is one `epStats` entry, a `Data` keyed by 5-tuple. "New flow"
  is the first time the collector sees a tuple.
- Numbers quoted are per node, on one core, from the benchmarks named.
  Paths are repo-relative; line numbers are omitted.

## What the evaluation is for

The dataplane enforces policy and reports the enforced verdict per flow
through NFLOG (iptables, nftables) or BPF events. Staged policies are
not enforced, so their verdict has to be computed in user space: for
each flow, the collector asks the engine what the policy set *including
staged policies* would do, and exports that as the flow's pending
policies. Policy preview, staged-policy impact and policy
recommendations consume it.

That makes the engine's cost part of the collector's per-flow budget.
The collector handles every flow on one goroutine; on a node that opens
10,000 new flows per second the whole budget for a new flow — conntrack
update, NFLOG, aggregation and the pending-policy evaluation — is
100 µs. On very large policy sets (tens of thousands of rules that apply
to every endpoint) one evaluation of a flow that matches no rule cost
milliseconds before the work tracked in CORE-13316 started, so the
collector fell behind at a few hundred flows per second.

## The evaluation paths today

Both paths run on the collector's main goroutine and both end in
`evaluatePendingRuleTraceForLocalEp`, which evaluates ingress when the
destination is a local workload and egress when the source is:

1. **Initial.** `getDataAndUpdateEndpoints` creates the `Data` for a new
   tuple and evaluates it once, inline. This is the path on the per-flow
   budget.
2. **Recalc.** In `FlowLogsPolicyEvaluationMode: Continuous` a ticker at
   0.8 × `FlowLogsFlushInterval` starts a sweep over every live flow.
   `snapshotFlowsForRecalc` copies the `epStats` pointers;
   `processRecalcBatch` then evaluates them in 100 ms batches that
   compete fairly with the other `select` cases, so a sweep cannot
   starve the loop but it can take as long as it takes. A flow evaluated
   within the last half recalc interval is skipped, as is one whose
   `Data` is no longer current.

Both take the store's read lock for the duration of one evaluation. The
store is fed by a separate goroutine (`loopProcessingDataplaneInfoUpdates`)
under the write lock, and swapped wholesale on resync by the
`PolicyStoreManager`.

**Invariants that hold today and that this design keeps:**

- `epStats` and every field of every `Data` are owned by the main
  goroutine. No other goroutine reads or writes them. That is why
  `Data` carries no mutex.
- An evaluation observes one consistent store: it runs under the read
  lock, and `ProcessUpdate` runs under the write lock.
- A failed evaluation (the engine returns an error, e.g. a policy the
  endpoint names is missing from the store) leaves the flow's previous
  trace in place. An empty trace would claim "no pending policy", which
  is a stronger claim than "could not work it out".

## The performance target and how it is measured

The requirement says 10,000 flows/s per node. On its own that number
does not say which flows, on what policy set, measured where. Three
levels pin it down, all built from one generator so that a number at one
level predicts the next:

| Level | What runs | Where | KPI | Pass |
|---|---|---|---|---|
| **K1 Engine** | `checker.Evaluate` on the reference store; the flow that misses every rule, and typical matching flows | `BenchmarkEvaluate*` in `app-policy/checker` | ns per evaluation, allocs per evaluation, ns per rule | miss-all ≤ 100 µs |
| **K2 Collector** | A real `collector` with a fake lookups cache and a loaded store, driven by conntrack updates for N new flows/s with M live flows | `BenchmarkCollectorPolicyEval` in `felix/collector` | main-loop time per new flow; sweep time per live flow; derived sustainable flows/s | 10k new flows/s; sweep < 10% of loop time |
| **K3 Node** | One Felix on a cluster, the reference set applied as Calico resources, a flow generator driving N new flows/s through local workloads | Banzai GCP kubeadm scale profile | `felix_collector_policy_eval_*` rates and the backlog gauge, Felix CPU and RSS, flow-log completeness, sampled `pending_policies` correctness | 10k flows/s for 30 min, no backlog growth, zero verdict errors |

**The reference policy set** is `policyscale.Composite()`: the two
rule-set shapes measured (anonymised) in a large production deployment,
applied to one endpoint. Ingress is the *baseline* shape — 294 policies
of 68 rules, almost all Pass, a quarter referencing one of 3,708 IP
sets; egress is the *allow-list* shape — 301 policies of 62 rules, each
a Pass on a destination CIDR or IP set plus a handful of ports from the
measured port distribution. Per direction that is ~20k and ~18.7k rules,
7,571 IP sets in all. `policyscale` renders it as a `PolicyStore` for K1
and K2, as `ToDataplane` updates for loading through `ProcessUpdate`,
and as `Tier` / `GlobalNetworkPolicy` / `GlobalNetworkSet` resources for
K3 (`hack/cmd/policyscale`). The parameters stay tunable so the
supported upper bound can be explored.

**The flow model** (`policyscale.Sampler`): new-flow rate is the primary
axis; destinations and ports are drawn from the fixture so the verdict
mix follows the rule mix (mostly matches deep in the walk, a
configurable fraction that misses every rule); a *repeat fraction*
re-emits an earlier flow on a new source port, the way clients
reconnect, because it decides whether a verdict cache helps; flow
lifetime controls the live population the sweep has to cover.

**Two budgets, not one.** The initial path has the per-flow budget
above. The sweep has its own: at 10k new flows/s even a 30 s mean flow
life leaves ~300k live flows, and re-evaluating all of them every
240 s at 2 ms each needs ~570 s of loop time per sweep — the sweep can
never finish. So the target needs three levers together: a faster
engine, evaluation off the main goroutine, and re-evaluating only the
flows whose inputs changed.

## Correctness gates

Every optimisation is a second implementation of the same function, and
verdict correctness is the one thing the requirement forbids trading
away. Two gates, both in `app-policy/checker`, and any new evaluator
runs through both before it is switched on:

- **Differential corpus** (`TestEvaluateAgreesWithOracle`,
  `assertEquivalent`): flows drawn from each preset — the denied flow,
  flows aimed at every N-th rule, sampled flows, replays as UDP and
  with an invalid protocol or a nil address — through two evaluators
  in both scopes; every trace must match. One evaluator is
  `policyscale.Fixture.Expect`, an oracle that answers from the
  generator's own model of each rule, not from the proto the engine
  reads. A cached or compiled engine is checked against the plain one
  the same way.
- **Named cases** (`runNamedCases`): what a generated corpus cannot
  reach — nil addresses against positive and negated references, named
  and negated named ports, IP+port sets, negated and missing sets,
  protocols out of range / by name / by number / negated, staged
  policies in both scopes, HTTP criteria against an L4 flow, Log rules,
  Pass into the next tier and into profiles, a policy missing from the
  store.

## The verdict cache

Shipped behind `FlowLogsPolicyEvaluationCacheSize` (default on, 65,536
entries; a config-file / environment-variable parameter, see
[Backport constraints](#backport-constraints)).

**Why it is sound.** A verdict is a function of (a) the endpoint's
applicable rules, (b) the store's IP sets and (c) the flow. For a flow
with no L7 attributes and no peer identity — every flow the collector
evaluates — the criteria in `match()` reduce to protocol, source and
destination address, destination port and, only where some rule looks
at it, source port; identity and HTTP criteria match such a flow
whatever the rule says. (a) and (b) are covered by the store
**generation**: `PolicyStore.Generation` moves on every `ProcessUpdate`
but `InSync`, and a `VerdictCache` is valid for exactly one generation
— it starts over when it sees a new one. (c) is the key: endpoint
pointer, scope, direction, protocol, addresses, destination port, and
source port only when `endpointMatchesSourcePorts` says a rule that can
apply to the endpoint in that scope and direction matches on it
(decided once per endpoint, scope, direction and generation).

**What it does not do.** Flows carrying identity or HTTP attributes
(Dikastes requests) and flows with a nil address bypass it. Failed
evaluations are not cached. The cache is bounded and starts over when
full (an LRU would keep hot entries at the cost of a list operation per
lookup; the flows a node sees repeat within a window far smaller than
the capacity). Invalidation is deliberately coarse — an IP set delta
anywhere empties it — which is safe; the sweep-invalidation work below
is where finer tracking belongs. The returned trace is shared between
callers; the collector copies it before storing it in `Data`.

**Observability.** `felix_collector_policy_eval_cache_{hits,misses,resets,evictions}_total`.
A hit ratio far below the traffic's repeat rate means the generation is
moving faster than flows repeat (heavy IP set churn); a high reset rate
says the same from the other side.

Measured on the composite set, egress, with the sampler's model: 1.0 ms
per evaluation uncached; 0.31 ms at a 50% repeat rate (62% hits);
0.08 ms at 90% (92% hits).

## Off-main-loop evaluation (planned)

The engine speed-ups get the miss-all case from milliseconds to hundreds
of microseconds; they do not get it to the tens of microseconds the
initial path can afford, and they do nothing for the sweep budget. The
evaluation has to leave the main goroutine.

**Shape.**

1. On the main goroutine, where a flow needs evaluation (initial or
   recalc), build a *request*: the `Data` pointer, its tuple, the source
   and destination `calc.EndpointData` already resolved, the store
   generation, and a per-flow sequence number. This costs microseconds
   and touches `epStats` only from its owner.
2. Hand it to a bounded worker pool through a channel. Workers take the
   store's read lock, look up the proto endpoint and call the engine —
   the same call the main loop makes today — and send a *result* (the
   request plus the trace or error) back on a results channel.
3. The main loop drains the results channel in its `select` and applies
   each one: only if the `Data` is still the current entry for its tuple
   and its sequence number is the flow's latest. Stale results are
   counted and dropped.

`epStats` and `Data` stay single-owner; workers never see a `Data`
field, only the request's copies. `Data` gains a sequence counter and an
"evaluation in flight" bit, both touched only by the main goroutine.

**Ordering.** Two evaluations of one flow can be in flight (an initial
request still queued when a sweep requeues it). The sequence number
makes the later request win regardless of which result arrives first;
an older result is dropped even though its verdict may be identical,
because the newer one was computed against a newer or equal generation.

**What is exported while an evaluation is pending.** Today a flow
exported before its first evaluation completes carries whatever
`IngressPendingRuleIDs` / `EgressPendingRuleIDs` hold, which for a new
flow is nothing. With evaluation asynchronous that window widens. The
proposal is an explicit "not yet evaluated" marker in the exported
pending-policies field rather than an empty or a stale value, so that
consumers can tell "no staged policy applies" from "not evaluated yet".
This is PMREQ-954's open Key Question 2 and needs product agreement
before implementation.

**Shedding.** The request channel is bounded (`backlog gauge`). Initial
requests are never dropped: if the channel is full the main loop
evaluates inline, as today, and counts it. Recalc requests are dropped
when the backlog is above a threshold and counted in
`felix_collector_policy_eval_deferred_total`; the flow keeps its last
trace and the next sweep tries again. So under overload the collector
degrades to today's behaviour for new flows and to slower refresh for
old ones, never to wrong verdicts and never to unbounded memory.

**Metrics.** Per-evaluation latency histogram (labelled `initial` /
`recalc`), backlog gauge, deferred counter, stale-result counter, worker
utilisation, plus the existing batch, flow and sweep-duration metrics.

**Configuration.** `FlowLogsPolicyEvaluationWorkers` (0 = evaluate on
the main goroutine, exactly today's path; default derived from
available CPUs) and `FlowLogsPolicyEvaluationBacklog`. Config-file /
environment-variable parameters first; `FelixConfiguration` fields on
master once the design has settled.

**Enterprise.** The Enterprise collector has a second evaluation call
site (`OnNewConnection` mode). It goes through the same request/result
path; the design must not assume one call site.

## Sweep invalidation (planned)

The sweep exists because a flow's verdict can change while the flow
lives: a staged policy edited, an IP set gaining or losing the flow's
peer. Today it re-evaluates every live flow every recalc interval to
find the few whose verdict moved. The store already knows what changed;
the plan is to make the sweep ask it:

- The store keeps a generation per policy (moved by its
  `ActivePolicyUpdate`) and per IP set (moved by `IPSetUpdate` and
  `IPSetDeltaUpdate`), and a *dirty CIDR trie* into which every added
  or removed IP set member is inserted, cleared once a sweep has
  consumed it.
- Each `Data` records the generations of the policies that applied to
  it and of the IP sets its verdict touched (the engine can report the
  set IDs it consulted), plus the generation at which it was last
  evaluated.
- The sweep re-evaluates a flow only if one of those generations moved
  or its source or destination address hits the dirty trie. Everything
  else is skipped at the cost of a few lookups.

The invariant that matters: **the cost of deciding whether a flow needs
re-evaluation must scale with the number of changes since the last
sweep, not with the number of flows or rules.** A design that walks the
rules to decide has only moved the problem. The differential harness
gates this too: after a change, a flow the oracle says moved must move
within one recalc interval (`D2` FVs on `flow_logs_goldmane_staged_test.go`).

## Backport constraints

This work ships to every active Enterprise release branch, the oldest
of which is ~2,800 lines behind master in the touched packages and on
an older Go toolchain. Every change here is therefore written
*backport-first*:

- No new `v3` API fields on release branches. New knobs are Felix
  config parameters readable from the config file or a `FELIX_*`
  environment variable (`local` in the `config:` tag); the
  `FelixConfiguration` field, which drags CRD and operator changes with
  it, lands on master only.
- Every optimisation sits behind a switch with a default chosen per
  branch: engine speed-ups on everywhere once the differential gates
  pass; the worker pool opt-in on the oldest branches until validated
  on a node and a customer cluster, then flipped in the following patch.
- Today's single-goroutine path remains reachable (`Workers: 0`) and is
  the fallback if anything goes wrong in the field.
- Nothing newer than the oldest branch's Go standard library.
- Changes are kept small enough to pick and review on their own.

## Common failure modes

- **Caching something the key does not cover.** If a rule criterion is
  added to `match()` that reads a new flow attribute, `verdictKey` must
  include it or `isL4Only` must exclude such flows. The named cases
  should gain a case that would fail without it.
- **Mutating the store without moving the generation.** Only
  `ProcessUpdate` moves it; a test or a future code path that edits
  `PolicyByID` or `IPSetByID` directly must bump `Generation` or the
  cache will answer from stale state.
- **Touching `Data` from a worker.** The single-owner rule has no lock
  behind it. Workers get copies in the request; results are applied by
  the main loop.
- **Reporting an empty trace on failure.** Keep the previous trace.
- **A benchmark whose walk is not what its name says.** Every benchmark
  asserts the trace it expects before the timed loop, so a fixture
  change cannot silently turn a full walk into an early exit.
- **Quoting one benchmark case as "the" number.** The tail-port,
  popular-port and denied cases move by different amounts under every
  change; report all three.

## Siblings that move with this doc

- `flow-logs-collector` (the collector as a whole; `epStats`
  ownership, export lifecycle) — the invariants above are that doc's
  invariants seen from the evaluation path.
- [`calc-graph.md`](./calc-graph.md) — the `LookupsCache` that resolves
  a tuple to endpoint data, and the `ToDataplane` messages the store
  is built from.
- `app-policy/checker` and `app-policy/policystore` are shared with
  Dikastes (application-layer policy); a change that is only safe for
  L4-only flows must say so and gate on it, as the cache does.
