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


# Felix flow-logs collector — Design

Design doc for the flow-logs collector: the code under
[`felix/collector/`](../collector/). Read it before editing that
tree or reviewing a PR that touches it.

The collector consumes per-flow counters from whichever dataplane is
running and turns them into flow logs. Its two upstream contracts are
documented elsewhere: endpoint and policy lookups come from the
`LookupsCache` built by the calculation graph
([`calc-graph.md`](./calc-graph.md)), and the BPF dataplane's
counter sources are described in
[`bpf-observability.md`](./bpf-observability.md). Build/test commands
are in [`felix/CLAUDE.md`](../CLAUDE.md); the whole-Felix overview is
in [`felix/DESIGN.md`](../DESIGN.md).

This doc is mostly about **which goroutine owns what**. The
collector's hard parts are not its data model; they are the ownership
rules that keep a lock-free hot path correct, and the cost shape of
the periodic sweeps that share that hot path.

## Conventions

- "WEP"/"HEP" = workload/host endpoint. "Local" = hosted on this node.
- A "flow" is one 5-tuple's worth of tracked state: a `Data` value in
  the `epStats` map, keyed by `tuple.Tuple`.
- "The collector loop" means the single `select` loop in
  `startStatsCollectionAndReporting` (`collector.go`). Unqualified
  "the loop" means the same thing.
- "Enforced" policy is what the dataplane actually applied. "Pending"
  policy is what *would* apply if the current datastore state were
  programmed — computed, not observed.
- Paths are repo-relative; type/function/field names are cited, line
  numbers omitted.

## What the collector is for

Felix's dataplane counts packets and bytes per flow, and records which
policy rules each flow hit. The collector's job is to turn those raw
counters into flow logs: correlate the counter sources for a flow,
attach the metadata a human or a UI needs (endpoint names, labels,
service, policy trace), aggregate flows that are alike, and hand the
result to one or more dispatchers.

Three properties shape the design:

**The inputs are separate and arrive out of order.** Conntrack gives
byte/packet counts and connection lifetime; NFLOG (or the BPF
equivalent) gives policy rule hits; the policy-sync channel gives L7
context. A flow log needs all of them, so the collector keeps
per-flow state and delays reporting until the picture is complete —
or until a deadline forces it out.

**Volume is unbounded by anything Felix controls.** A busy node can
hold hundreds of thousands of flows. Any per-flow work on a periodic
timer is therefore an O(all flows) sweep, and any such sweep sharing
the collector loop can starve the counter inputs.

**Counter input must not be dropped.** The reader channels are
buffered but finite. If the loop stalls, conntrack and NFLOG
information is lost, and lost input means wrong byte counts in a flow
log — not just a late one.

### Review notes

- Any new per-flow periodic work is an O(all flows) sweep. Ask where
  its time budget comes from before asking whether it is correct.
- A change that adds latency to the collector loop trades against
  reader-channel overflow. Buffer sizes are not the fix; not stalling
  is the fix.

## Data flow

```
dataplane counter sources          calc graph
  NFLOG / BPF policy events          LookupsCache (endpoints,
  conntrack / BPF conntrack            networksets, services, nodes)
  policy-sync DataplaneStats               |
        |                                  | (RWMutex, read-only here)
        v                                  v
  reader goroutines  --chans-->  ### collector loop ###
  (PacketInfoReader,             epStats: map[Tuple]*Data
   ConntrackInfoReader)          sole owner of every Data
                                         |
  DataplaneInfoReader                    | metric.Update
        |                                v
        v                          metricReporters
  policy-store goroutine                 |
  (PolicyStore, RWMutex)  <--read-- FlowLogReporter.Report
        ^                                | (SYNCHRONOUS on the loop)
        |                                v
        +--pending policy eval--   Aggregator.FeedUpdate
           (checker.Evaluate)       flowStore, flMutex
                                         |
                                         | flush ticker
                                         v  (reporter goroutine)
                                   GetAndCalibrate -> []*FlowLog
                                         |
                                         v
                                   dispatchers (goldmane, local socket)
```

Orientation files: `collector.go` (the loop, the flow cache),
`stats.go` (`Data`, `RuleTrace`), `dpstatshelper.go` (wiring),
`flowlog/reporter.go` and `flowlog/aggregator.go` (downstream),
`iptables.go` (NFLOG and netlink conntrack readers).

## Goroutine and ownership model

| Goroutine | Owns | Notes |
|---|---|---|
| Collector loop (`startStatsCollectionAndReporting`) | `epStats` and **every field of every `Data`** | The only writer of flow state. Never blocks on a lock it does not have to. |
| Reader goroutines (`PacketInfoReader`, `ConntrackInfoReader`) | their own state | Communicate by value over buffered channels. |
| Policy-store goroutine (`loopProcessingDataplaneInfoUpdates`) | `PolicyStore` writes | Guarded by `PolicyStoreManager`'s `RWMutex`. Already off the loop. |
| Reporter goroutine (`FlowLogReporter.run`) | `flowStore` flush half | Shares `Aggregator.flMutex` with the loop — see [Aggregation](#aggregation-and-reporting). |
| Calc graph | `LookupsCache` writes | `RWMutex`; the collector is a reader only. |

The load-bearing rule is the first row:

> **The collector loop is the sole owner of `epStats` and of every
> field of every `Data` it contains.** No other goroutine reads or
> writes them.

Everything in the collector that looks lock-free is lock-free because
of that rule. `Data` has no mutex. `RuleTrace` has no mutex.
`getDataAndUpdateEndpoints` mutates `SrcEp`/`DstEp` in place with no
synchronisation. `checkEpStats` deletes map entries while iterating
the map. All of it is correct only while single-owner holds.

Two shared caches are read from the loop and written elsewhere. Both
are safe, for reasons worth stating because they are what make the
proposed split in the last section tractable:

- **`LookupsCache`** (`calc/endpoint_lookup_cache.go` and siblings) is
  `RWMutex`-guarded, and on update it **replaces** the
  `endpointData` value for a key rather than mutating it. So an
  `EndpointData` interface value, once obtained, is immutable and can
  be held and read without further locking — including from another
  goroutine.
- **`PolicyStore`** is `RWMutex`-guarded via `PolicyStoreManager`, and
  policy evaluation is read-only against it: `checker.Evaluate`
  memoises into a per-call `requestCache`, never into the store.

### Review notes

- A PR that has any goroutine other than the collector loop touch
  `epStats` or a `Data` field is changing this model. It needs this
  section updated and a stated synchronisation scheme — not a lock
  added at the first place the race detector complained.
- Adding a mutex to `Data` or `RuleTrace` is a design change, not a
  fix. The alternative is almost always to hand data across a channel
  and keep single-owner.
- New reads of `LookupsCache` or `PolicyStore` from the loop are fine.
  New *writes* from the loop are not.
- Treat `-race` as necessary but not sufficient here: it only catches
  what a test actually drives concurrently.

## The flow cache: `epStats` and the `Data` lifecycle

`epStats` maps a 5-tuple to a `Data`. `Data` holds the endpoints, the
conntrack counters, an ingress and an egress `RuleTrace` (the enforced
policy hits, indexed by match position), the pending policy rule IDs,
and the bookkeeping timestamps and flags that drive reporting and
expiry.

**Creation** happens in `getDataAndUpdateEndpoints`, which is the
single entry point for "get me the flow for this tuple". It is
deliberately not a plain map lookup: it also refreshes the endpoint
data, because labels may have changed and so the policy matches may
differ. A new entry is created only if at least one endpoint is local,
and HEP-reported flows are skipped.

**Reporting** is gated. `reportMetrics(data, force=false)` refuses to
report while the picture is still incomplete — no service resolved
yet, no verdict rule seen yet, or a remote endpoint that might still
resolve to a NetworkSet or DNS name. Those flows wait for the export
ticker, which calls `reportMetrics(force=true)` once
`InitialReportingDelay` has passed since the last rule update. This
"wait a bit, then force" shape is the collector's answer to
out-of-order inputs, and it is where any new asynchronous per-flow
metadata belongs.

**Endpoint or rule changes** are handled by expiring the flow and
starting again: `handleDataEndpointOrRulesChanged` reports what it
has, sends an expire update, resets the conntrack counters and clears
`Reported` so the entry can be refilled.

**Expiry** has two paths. A conntrack entry that has gone away reports
and deletes immediately if it can, or sets `Expired` and lets the
export ticker deal with it. Separately, `checkEpStats` ages out
anything untouched for longer than `AgeTimeout` (or, in BPF mode, the
matching BPF conntrack timeout).

**Pre-DNAT cleanup** is the one cross-flow operation.
`checkPreDNATTuple` looks up a *second* tuple — the pre-DNAT form of
the current one — and may report, expire and delete that other entry.
It exists to stop a denied connection attempt that happens to look
like the pre-DNAT tuple of a long-running allowed connection from
living forever. It is safe today only because one goroutine owns the
whole map; see [the proposal](#planned-moving-policy-evaluation-off-the-loop).

### Review notes

- Do not bypass `getDataAndUpdateEndpoints` with a bare `epStats`
  lookup. The endpoint refresh it performs is part of correctness, not
  an optimisation.
- New per-flow metadata that arrives asynchronously belongs behind the
  `force=false` gate, alongside `foundService` and `VerdictFound`, so
  the existing delay-then-force machinery covers it.
- Any new cross-flow operation (like `checkPreDNATTuple`) is a
  constraint on future concurrency work. Call it out explicitly.
- `checkEpStats` is an untime-boxed O(all flows) sweep. Work added
  inside its loop is paid per flow per export interval.

## Publishing a `metric.Update`: the copy-on-write invariant

`sendMetrics` builds a `metric.Update` and passes it to every
registered reporter. The update does **not** deep-copy the flow's
policy state. It carries:

- `RuleIDs`, from `RuleTrace.Path()` — the trace's own
  `rulesToReport` slice;
- `PendingRuleIDs`, the `Data`'s `IngressPendingRuleIDs` /
  `EgressPendingRuleIDs` slice;
- `SrcEp` / `DstEp`, `EndpointData` values from the `LookupsCache`.

So a published `metric.Update` aliases live flow state. That is safe,
and the reason it is safe is an invariant that nothing in the code
currently states:

> **Policy slices reachable from a `metric.Update` are replaced
> wholesale, never mutated in place.** `addRuleID` and `replaceRuleID`
> set `rulesToReport = nil` and let the next `Path()` rebuild it.
> Pending evaluation does
> `*ruleIDs = append([]*calc.RuleID(nil), trace...)` — a fresh
> allocation. `LookupsCache` replaces `endpointData` values rather
> than mutating them.

Copy-on-write is what lets a captured slice stay valid after the flow
moves on. The obvious "optimisations" break it silently: reusing the
slice with `*ruleIDs = (*ruleIDs)[:0]` and appending, or filling
`rulesToReport` in place, would corrupt whatever update is still
holding it. Nothing would panic; flow logs would just report the
wrong policies, occasionally.

A second, narrower rule:

> **`RuleTrace.Path()` is a mutating read.** It lazily populates
> `rulesToReport` and `hasDenyRule`. It must only be called by the
> `Data`'s owner. `sendMetrics` satisfies this; a reporter that called
> `Path()` on a retained trace would not.

Today the aliasing is also protected by timing: `Report` is
synchronous on the collector loop, and `Aggregator.FeedUpdate` copies
everything it needs into string-keyed sets (`newPolicySet`) before
returning. Copy-on-write is the part that survives if that timing
changes; do not rely on the timing.

### Review notes

- Reject in-place mutation or reuse of `rulesToReport`,
  `IngressPendingRuleIDs` or `EgressPendingRuleIDs`. Slice reuse here
  is a correctness bug wearing an optimisation's clothes.
- A new field on `metric.Update` that points at mutable `Data` state
  needs either copy-on-write on that field or a deep copy at publish.
- `Path()` calls belong on the owning goroutine only.
- A reporter must not retain anything reachable from the update past
  its `Report` call unless the field is documented copy-on-write.

## Pending policy evaluation (continuous mode)

When `PolicyEvaluationMode` is `Continuous`, each flow log carries not
only the policies the dataplane enforced but also the policies that
*would* apply under current datastore state. That second trace is
computed, by running `checker.Evaluate` — the same evaluator
`app-policy` uses — over the flow against the `PolicyStore`.

The cost shape is what matters. Evaluation is O(tiers × policies ×
rules) per flow per direction, allocates a `requestCache` per call,
and does selector matching inside. It runs in two places:

- **Once when a flow is created**, inline in
  `getDataAndUpdateEndpoints` (`policyEvalInitial`), so a flow's first
  flow log always carries pending policies.
- **Periodically for every flow**, on `tickerPolicyEval` at 8/10 of
  the flush interval (`policyEvalRecalc`).

The periodic pass is a full O(all flows) sweep of the most expensive
per-flow work in the collector, on the loop that must not stall. It is
therefore **time-boxed** rather than run to completion:

1. On the tick, `snapshotFlowsForRecalc` copies `*Data` pointers into
   `recalcSnapshot` and the tick channel is masked off.
2. A pre-closed `batchReady` channel then drives `processRecalcBatch`
   as one more case in the same `select`, so each ~100 ms batch
   competes with conntrack, NFLOG, export and dataplane-stats work
   instead of starving them.
3. When the snapshot drains, the batch channel is masked and the
   ticker is re-armed. Only one sweep is ever in flight.

Three details in that loop are easy to break:

- **Every batch must pop at least one flow**, or a sweep can fail to
  progress. The deadline check after evaluation is deliberately
  *after*.
- **Skips must also be bounded.** A flow that is skipped never reaches
  the post-evaluation deadline check, so a snapshot of pure skips
  would drain in one batch however large it is — reintroducing the
  stall through the skip path. Hence the pre-pop deadline check,
  amortised over `policyEvalDeadlineCheckInterval` pops because
  reading the clock costs several times more than deciding to skip.
- **Freshness is judged when the sweep reaches a flow**, not when the
  snapshot is taken, so a flow that becomes due mid-drain is still
  picked up. `lastPolicyEvalAt == 0` is checked explicitly: `monotime`
  counts from boot, so early in uptime the "too recent" threshold is
  negative and a never-evaluated flow would otherwise look fresh.

The sweep also re-checks that each flow is still the live entry for
its tuple (`epStats[data.Tuple] != data`), because interleaved batches
mean the map has moved on since the snapshot.

Because the whole thing runs on the goroutine that owns `epStats`, it
needs no locks. That is the property the proposal below has to buy
back some other way.

### Review notes

- The ticker must stay nil when pending policies are disabled. A live
  ticker means a full sweep per tick for no benefit; `policyEvalTickChan`
  returning nil is what masks the sweep out of the `select`.
- Preserve both progress guarantees: at least one pop per batch, and a
  bounded run of skips.
- Tests that call the sweep methods directly do not prove the sweep is
  reachable. Keep at least one test driving it through the `select`
  loop, so a masked or stopped ticker fails.
- New per-flow work inside the sweep needs its cost compared against
  the batch budget, not just measured in isolation.

## Aggregation and reporting

`LogMetrics` fans the update out to every registered reporter
synchronously. For flow logs that is `FlowLogReporter.Report`, which
calls `Aggregator.FeedUpdate` for each configured aggregator (allow
and deny, per dispatcher).

**`FeedUpdate` runs on the collector loop.** Per update it filters on
allow/deny, builds a `FlowMeta` (endpoint metadata, service
resolution), builds the policy sets — `newPolicySet` does a
`fmt.Sprintf` **per rule in the trace**, for the enforced and the
pending sets — and then takes `Aggregator.flMutex` to merge into
`flowStore`.

That mutex is the collector's other latency exposure.
`GetAndCalibrate`, on the reporter's own flush goroutine, holds the
same lock while converting the **entire** flow store to `FlowLog`s and
garbage-collecting it. So on each flush interval the collector loop
can block behind a whole-store conversion — on the hot report path,
not on a periodic sweep.

Downstream of that boundary, everything is already off the loop:
`GetAndCalibrate` and the dispatchers (`goldmane`, local socket) run
on the reporter goroutine, and both dispatchers push into a client
queue rather than doing network I/O inline.

### Review notes

- Work added to `FeedUpdate`, `NewFlowMeta` or `newPolicySet` is paid
  on the collector loop, once per update per accepting aggregator.
- Work added under `flMutex` in `GetAndCalibrate` lengthens a stall on
  the collector loop. Prefer doing it outside the lock.
- A reporter's `Report` is called on the collector loop. It must not
  block on I/O.

## Planned: moving policy evaluation off the loop

*Not implemented. Recorded here so the ownership rules above are read
alongside the change that will bend them.*

Time-boxing bounds the sweep's interference but does not remove it:
batches still add up to ~100 ms of latency to counter handling, and
the evaluation still time-slices one core with the work it is
competing against. The next step is a second goroutine.

### Why not shard `epStats`

The obvious plan — shard the map, one lock per shard, two goroutines
touching different shards — does not fit this code:

- **The worker barely touches the map.** Its only `epStats` access is
  the liveness re-check. A `deleted` flag on `Data`, set by the
  loop, replaces it. Sharding a map to protect one lookup is a lot of
  machinery for nothing.
- **The real shared state is the `Data` fields**, which a shard lock
  only covers if the loop holds it across nearly all of
  `handleCtInfo`, `applyPacketInfo` and `checkEpStats` — those read
  and write `SrcEp`/`DstEp` and the pending slices throughout. "Lock
  per shard" then means "ownership of every `Data` in the shard", with
  lock traffic on every hot-path event.
- **`checkPreDNATTuple` needs two shards at once.** It reaches from
  one entry to a different tuple, which hashes to a different shard,
  and deletes it. That demands an explicit lock ordering, or
  restructuring into "collect victims, release, then process".
- **The sweep must not hold a shard lock while evaluating.** Doing so
  divides the stall by the shard count instead of removing it — so
  you snapshot per shard anyway, at which point the map lock has
  stopped being the point.
- **`reportEpStatsCacheMetrics` calls `len(epStats)`** on every insert
  and delete. Sharded, that becomes a sum over shards on the hot path
  and needs an atomic counter instead.

### The intended shape: hand over, don't share

The snapshot already exists, so the handover point is already built.
Instead of draining `recalcSnapshot` in batches, send it:

1. **Loop → worker:** on the tick, snapshot
   `(data, srcEp, dstEp, prevIngressIDs, prevEgressIDs)` per due flow
   and send the batch.
2. **Worker:** endpoints are supplied, so no `LookupsCache` lookup is
   needed for evaluation; run `checker.Evaluate` under the policy-store
   read lock; compare against the previous IDs and return only the
   flows whose trace actually changed.
3. **Worker → loop:** on results, re-check the entry's identity in
   `epStats` and that the endpoints still match what the worker
   evaluated against, then store the traces and stamp
   `lastPolicyEvalAt`.

Shared mutable state: two channels. The single-owner rule survives
intact — the worker never reads or writes a `Data`. Most flows will
not have changed, so the apply pass is cheap, and it can be
time-boxed with the machinery that exists today. `EndpointData`
immutability and the read-only `PolicyStore` (see
[Goroutine and ownership model](#goroutine-and-ownership-model)) are
what make step 2 safe without locks.

### The one behaviour change to agree first

The initial evaluation is currently inline on flow creation, which is
why a flow's first log always carries pending policies — and it is
also where most of the per-flow cost lands on a busy node, so it is
the part most worth moving. Moving it lets a short-lived flow report
before its pending trace exists, producing a flow log with an empty
pending policy set.

The fix fits the existing pattern: gate non-forced `reportMetrics` on
a "pending evaluated" flag alongside `foundService` and
`VerdictFound`, so the delay-then-force machinery already described
covers it. This changes observable output in the short-lived-flow
case and should be agreed, not assumed.

## Known rough edges

Pre-existing, found while writing this doc. Recorded so they are not
mistaken for design.

- **The BPF expiry clamp in `checkEpStats` is dead code.**
  `if minExpirationAt < 2*bpfconntrack.ScanPeriod` compares an
  absolute `monotime` value against a bare 20 s duration. Once uptime
  exceeds 20 s the condition is always false, so the intended floor —
  "never expire a flow sooner than two BPF conntrack scan periods" —
  never applies. The intent reads as
  `now - minExpirationAt < 2*ScanPeriod`.
- **Pending rule IDs survive an endpoint change.**
  `handleDataEndpointOrRulesChanged` resets the conntrack counters and
  `Reported`, but leaves `IngressPendingRuleIDs`,
  `EgressPendingRuleIDs` and `lastPolicyEvalAt` alone. Between the
  change and the next sweep reaching that flow, it can report a
  pending trace computed against the old endpoint. The freshness skip
  can make that window most of a flush interval.
- **`newPolicySet` re-formats per rule, per accepting aggregator.**
  The `fmt.Sprintf` per rule is redone for each aggregator that
  accepts the update, on the collector loop.

## Testing

`collector_test.go` drives the collector directly and reaches into
`c.epStats` extensively; that is deliberate — it is the flow cache's
contract under test. Keep it working rather than routing tests around
it, because a change that forces a rewrite of those accesses is
usually a change to the ownership model and deserves the scrutiny.

- Prefer vanilla `go test` for new files here; the package is not
  Ginkgo-first.
- Anything touching the sweep needs at least one test that goes
  through the `select` loop, not just a direct method call.
- Concurrency changes need a test that actually drives both
  goroutines against the same flows. `-race` finds nothing a test does
  not exercise. A request/response design is testable
  deterministically — inject the worker and control the response
  channel — which is a reason to prefer it over shared state.

## Common failure modes

1. **Stalling the collector loop** — a new O(all flows) sweep, an
   unbounded batch, or blocking I/O in a `Report` implementation.
   Lost counter input means wrong byte counts, not just late logs.
2. **Reusing a policy slice in place** — breaks copy-on-write and
   silently corrupts flow logs that are still holding it.
3. **Touching `Data` from a second goroutine** without changing the
   ownership model, then adding a lock where the race detector
   pointed.
4. **Reporting before the picture is complete** — new asynchronous
   metadata that does not go behind the `force=false` gate shows up as
   missing fields in flow logs.
5. **A sweep that cannot make progress** — losing the at-least-one-pop
   guarantee, or letting a run of skips ignore the deadline.

## Keep this document in sync with the code

The repo-wide doc-update rule
([`.claude/CLAUDE.md` → Documentation map](../../.claude/CLAUDE.md),
mirrored in
[`.github/copilot-instructions.md`](../../.github/copilot-instructions.md))
applies. For the collector, "changes how it works" means: a change to
which goroutine owns `epStats` or `Data`; a new field on
`metric.Update` or a change to what a published update aliases; a
change to the reporting gates or the expiry paths; a new or altered
periodic sweep, or a change to how one is time-boxed; or a change to
where aggregation runs. Update the relevant section here in the same
PR, and update [`felix/DESIGN.md`](../DESIGN.md) if the sub-design's
scope changes.
