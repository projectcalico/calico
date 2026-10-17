<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Flow logs — the collector

The collector turns dataplane events into flow logs. It is the only part of
Felix whose output is a *stream of records for humans and downstream systems*
rather than kernel state, which gives it a different shape from the rest of
the agent: no resync loop, no idempotent-apply doctrine, and an accounting
model that trades exactness for bounded memory.

That trade is the single most important thing to understand here. The
collector is a **lossy aggregator by design** — it collapses many
connections into one record, resets its counters every flush, and garbage
collects state it believes is finished. Most of the invariants below exist to
say precisely *where* the loss is allowed to happen, because code and tests
that assume exactness break intermittently rather than loudly.

One of several Felix sub-designs; see [`felix/DESIGN.md`](../DESIGN.md).

## Pipeline

```
dataplane event sources          per-connection state         aggregation            dispatch
─────────────────────            ────────────────────         ───────────            ────────
NFLOG          ─┐                                             Aggregator (allow) ─┐
conntrack poll ─┼─► PacketInfo ─► collector.epStats ─► metric  Aggregator (deny)  ─┼─► goldmane
BPF verdict    ─┤   ConntrackInfo   map[Tuple]*Data    .Update                     └─► local socket
BPF conntrack  ─┘
```

Three stages, each with its own lifetime and its own notion of "done":

1. **Per-connection tracking** (`collector.go`, `stats.go`) — one `Data` per
   5-tuple in `c.epStats`, carrying byte/packet counters and the rule trace
   that resolves the policy verdict. Lives as long as the connection, plus a
   grace period.
2. **Aggregation** (`flowlog/aggregator.go`, `flowlog/types.go`) — many
   `Data` collapsed into one `FlowSpec` per `FlowMeta` key. Lives for one
   flush interval, then resets or is deleted.
3. **Dispatch** (`flowlog/reporter.go`, `goldmane/`, `local/`) — each
   exportable entry rendered to one or more `FlowLog` records and written
   out. Stateless.

Everything crosses stage boundaries as a `metric.Update` (`types/metric/`),
which carries an `UpdateType` of either `UpdateTypeReport` or
`UpdateTypeExpire`. Those two values drive the whole accounting model, so
read `aggregateFlowStats` before changing anything that emits them.

### Review notes

- The stages have deliberately different lifetimes. A fix that "keeps state
  a bit longer" in one stage to paper over a symptom in another is almost
  always wrong — find which stage lost the information.
- `metric.Update` is passed by value into `Report` and by pointer into
  `FeedUpdate`. It is not safe to retain the pointer past the call.

## Event sources

The collector does not read the kernel itself. It consumes two interfaces,
wired per dataplane in `dataplane/linux/int_dataplane.go`:

| | `PacketInfoReader` (policy verdicts) | `ConntrackInfoReader` (counters + lifecycle) |
|---|---|---|
| iptables / nftables | `NewNFLogReader` — NFLOG groups 1 (ingress) and 2 (egress) | `NewNetLinkConntrackReader` — netlink conntrack poll, every `ConntrackPollingInterval` (default 5s) |
| BPF | `events.NewCollectorPolicyListener` — `TypePolicyVerdict` ring-buffer events | `bpfconntrack.NewCollectorCtInfoReader` |

Two consequences worth holding onto:

**The BPF conntrack reader must be registered before the liveness scanner.**
`int_dataplane.go` does this deliberately — the liveness scanner would delete
expired entries before the collector ever saw them, so the collector's reader
is inserted upstream of it in the scanner chain.

**"Expired" does not mean "gone from the kernel".** In the iptables path,
`ConvertCtEntryToConntrackInfo` (`iptables.go`) marks a TCP entry expired as
soon as it reaches `TCP_CONNTRACK_TIME_WAIT`:

```go
entryExpired := (ctTuple.ProtoNum == nfnl.TCP_PROTO &&
        ctEntry.ProtoInfo.State >= nfnl.TCP_CONNTRACK_TIME_WAIT)
```

The kernel keeps that entry for roughly another 120s. So a short-lived
connection — anything closed by the client, which is most probes and health
checks — is reported *expired* almost immediately while remaining visible to
the next several conntrack polls, and any later NFLOG for the same tuple can
rebuild a fresh `Data`. This is the root of the double-count discussed under
[Flow-start accounting](#flow-start-accounting).

### Review notes

- A change to either reader's expiry criterion changes flow-start accounting
  downstream. Trace the effect through `aggregateFlowStats` before landing it.
- The two dataplanes deliver verdicts through different transports but must
  produce equivalent `metric.Update`s. A new field on `metric.Update` needs
  populating on both paths, or BPF-mode flow logs silently lose it.

## Stage 1 — per-connection state

`c.epStats` is `map[tuple.Tuple]*Data`. `getDataAndUpdateEndpoints` creates
entries for live flows and refuses to create them for expired ones — an
expired update with no existing entry is a no-op, which is what makes the
TIME_WAIT tail harmless *until* something else recreates the entry.

A `Data` accumulates conntrack counters (forward and reverse), application
counters, the ingress and egress **rule traces** — each of which resolves to
a verdict once its final rule is seen — and endpoint metadata (`SrcEp`,
`DstEp`) plus service info.

### Report and expire

Two timers in `checkEpStats` govern the lifecycle, both from
`felix/config/config_params.go`:

| Knob | Default | Meaning |
|---|---|---|
| `InitialReportingDelay` | 5s | Wait this long after the last rule update before reporting, so the full rule trace and async metadata (service) have landed. |
| `AgeTimeout` | 10s | Expire and delete a `Data` untouched for this long. In BPF mode this is replaced per-protocol by the BPF conntrack timeouts, floored at `2 × bpfconntrack.ScanPeriod`. |

`reportMetrics(data, force)` refuses to report when `force` is false and any
of these is still unresolved: the service lookup, the local endpoints'
verdict rules, or the remote endpoint identity. Those cases fall through to
the ticker, which forces the report once `InitialReportingDelay` has passed.
`expireMetrics` only emits when `data.Reported` is already true — an `Expire`
is never sent for something that was never reported.

Three paths reach a report, and the differences matter:

1. **Ticker** (`checkEpStats`) — the normal path; forced report after the
   delay, then expire-and-delete once aged out.
2. **Conntrack expiry** (`applyConntrackStatUpdate`) — on an expired entry,
   report + expire + `deleteDataFromEpStats` immediately if reportable;
   otherwise flag `Expired` and let the ticker finish the job.
3. **Rule or endpoint change** (`handleDataEndpointOrRulesChanged`) — when
   `AddRuleID` returns `RuleMatchIsDifferent`, the current stats are reported
   and expired, counters are reset, and **`Reported` is set back to false**
   so the same connection reports again under its new rule match.

Path 3 is easy to miss: it means one connection can legitimately produce more
than one report/expire pair within a flush interval, without the connection
ever restarting.

### Review notes

- `expireMetrics` is gated on `Reported`; do not send an `Expire` for
  never-reported data. The aggregator's completed-refs set would count a
  completion for a flow it never saw start.
- Anything added to `Data` that participates in reporting must also be reset
  on the path-3 reset (`ResetConntrackCounters` and friends), or it
  double-counts across the re-report.
- `getDataAndUpdateEndpoints` is not a cheap map lookup — it refreshes
  endpoint data from the lookups cache. Do not call it in a loop.

## Stage 2 — aggregation

`FeedUpdate` computes a `FlowMeta` from the update and the aggregation level,
then either creates a `FlowSpec` or merges into the existing one.

### Aggregation level

`AggregationKind` (`flowlog/aggregator.go`) decides what the `FlowMeta` key
contains, and therefore how much collapsing happens:

| Level | Collapses |
|---|---|
| `FlowDefault` | nothing — source port is part of the key, so one bucket per connection |
| `FlowSourcePort` | source port |
| `FlowPrefixName` | source port and endpoint name (aggregated to the prefix) |
| `FlowNoDestPorts` | the above plus destination port |

**`NewAggregator` fixes the level at `FlowPrefixName`, and nothing changes it
at runtime.** There is no setter and no dynamic adjustment, so the other
three values are defined but currently unreachable — as is the
level-mismatch branch in `calibrateFlowStore` that marks entries
non-exportable when `entry.aggregation != newLevel`. Treat that machinery as
reserved rather than dead: it is the seam a configurable or adaptive level
would use, and `MergeWith`/`ContainsActiveRefs` exist to keep flow counts
accurate across such a change.

The practical consequence of being pinned at `FlowPrefixName` is that **a
`FlowMeta` never corresponds to a single connection** — source port is not in
the key, and endpoint names are collapsed to their prefix. Every count in a
record is therefore a count across many connections by construction.

### Aggregators are per-action, keyed on `HasDenyRule`

`configureFlowAggregation` (`dpstatshelper.go`) builds a separate
`Aggregator` for allow and for deny, per dispatcher. `FeedUpdate` filters on
`mu.HasDenyRule` rather than the final verdict, deliberately: a *staged* deny
then aggregates on the deny side even while the effective verdict is still
allow, so turning a staged policy into an enforced one does not move its
traffic between aggregators.

### Flow-start accounting

`FlowStats` embeds four tuple sets (`flowReferences` in `flowlog/types.go`):

| Set | Meaning | On flush |
|---|---|---|
| `flowsStartedRefs` | tuples that *started* this interval | cleared |
| `flowsCompletedRefs` | tuples that *completed* this interval | cleared |
| `flowsRefsActive` | tuples currently active | **kept** |
| `flowsRefs` | tuples active at any point this interval | reset to `flowsRefsActive` |

`aggregateFlowStats` maintains them:

```go
case metric.UpdateTypeReport:
        if !f.flowsRefsActive.Contains(mu.Tuple) || f.flowsStartedRefs.Contains(mu.Tuple) {
                f.flowsStartedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
        }
        f.flowsRefsActive.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
case metric.UpdateTypeExpire:
        f.flowsCompletedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
        f.flowsRefsActive.Discard(mu.Tuple)
```

`flowsRefsActive` surviving the flush is what normally makes a long-lived
connection count as *one* start, in the first interval only. The reported
`NumFlowsStarted` is just `flowsStartedRefs.Len()`.

**Where the exactness ends.** `calibrateFlowStore` deletes the entire
`flowStore` entry when no active refs remain:

```go
remainingActiveFlowsCount := entry.spec.GarbageCollect()
if remainingActiveFlowsCount == 0 {
        delete(a.flowStore, flowMeta)
        return
}
```

So the pair (`FlowStats.reset` keeps `flowsRefsActive`; `calibrateFlowStore`
deletes the bucket when it is empty) has a gap: a `Report` for a tuple that
arrives in a *later* flush interval than that tuple's `Expire` finds no
bucket, builds a fresh one, and counts a **second** start for the same
connection. Combined with the TIME_WAIT early-expire above, every short-lived
TCP connection is exposed to this — it only needs one late dataplane event
for its 5-tuple (an NFLOG batch landing on the far side of the conntrack
poll, or a path-3 re-report from rule churn).

At the default 300s flush interval and `FlowPrefixName` aggregation this is a
small inflation of `numFlowsStarted`, not a correctness cliff. It is written
down because the contract it implies is narrower than the field name suggests:

> `NumFlowsStarted` counts flow starts observed per tuple per flush interval
> during which the flow was active. It is **not** a count of TCP connections,
> and it is not stable across flush boundaries.

### Review notes

- A new field in `FlowReportedStats` must be handled in **both**
  `FlowReportedStats.Add` and `FlowStats.reset`. Add-only means it
  accumulates forever across flushes; reset-only means it never reaches a
  record.
- Do not delete non-exportable entries in `calibrateFlowStore`. They are what
  would keep `NumFlows` accurate if the level ever became adjustable.
- Any change to the four reference sets is a change to the published contract
  of `numFlows*`. Update the table above and say so in the release note.
- `FeedUpdate` holds `flMutex` for the whole update. Do not add I/O,
  lookups-cache calls, or anything that can block underneath it.

## Stage 3 — reporters and dispatchers

`FlowLogReporter` owns a jittered flush ticker (`FlowLogsFlushInterval`,
default 300s, jitter `interval/10`). On each tick it walks its aggregators,
calls `GetAndCalibrate`, and hands the resulting `[]*FlowLog` to each
dispatcher registered for that aggregator.

Dispatchers (names in `dpstatshelper.go`):

| Dispatcher | Target |
|---|---|
| `goldmane` | gRPC to the goldmane aggregator (see [`goldmane/DESIGN.md`](../../goldmane/DESIGN.md)) |
| `socket` | local socket, for in-cluster consumers |

`AddAggregator` panics on an unknown dispatcher name — a wiring typo is a
code error, deliberately not a silent no-op.

### Review notes

- Dispatchers are started lazily and retried on the health tick; `Start`
  failing is not fatal. Do not add a dispatcher that panics on a transient
  target failure.
- `Report` on a dispatcher is called with the whole batch under no lock;
  dispatchers must not mutate the `[]*FlowLog` they are given, since every
  dispatcher for an aggregator receives the same slice.
- The reporter has no queue it can grow and no way to shed load. If you add a
  slow dispatcher, the flush loop is what pays for it.

## Invariants

1. **`NumFlowsStarted` is per-tuple-per-interval, not per-connection.** See
   [Flow-start accounting](#flow-start-accounting). No consumer or test may
   assert exact equality against a count of connections it made.
2. **An `Expire` is only ever sent after a `Report`** for the same `Data`
   (`expireMetrics` gates on `Reported`).
3. **Expired updates never create state.** `getDataAndUpdateEndpoints`
   returns the existing `Data` or nil for expired updates; it never inserts.
4. **"Conntrack expired" precedes kernel entry removal.** For TCP it fires at
   `TIME_WAIT`; the entry remains pollable for ~120s afterwards.
5. **A `Data` is reported at most once per rule-match generation.** A changed
   rule match reports, expires, resets counters and clears `Reported`, rather
   than mutating an already-reported record.
6. **Allow and deny aggregate separately, keyed on `HasDenyRule`** — not on
   the effective verdict, so staged policies do not move between aggregators.
7. **Both dataplanes must produce equivalent `metric.Update`s.** The
   transports differ (NFLOG + netlink poll vs. ring-buffer events + BPF
   conntrack); the record contract does not.

## Testing

Unit tests live beside the code; `flowlog/` and the collector itself have
substantial coverage of the aggregation state machine, which is the right
level for anything touching the reference sets.

FVs live in `felix/fv/flow_logs*_test.go` and share a harness,
`felix/fv/flowlogs/flow_tester.go`. One property of that harness has produced
long-lived flakes and is worth knowing before writing a flow-log FV:

**`FlowTester` include filters are OR'd, not AND'd** (`Includes
[]IncludeFilter`, documented in the field comment as "Set of filters is
ORed"). "Reporter X *and* port Y" is not expressible. A filter built only
from reporter types will admit every host-network flow on the node when those
reporters are the plain `src`/`dst` values, and any admitted flow the test
does not explicitly check is reported as an `Unchecked flow` failure. Prefer
`IncludeByDestPort` for tests that own a known port.

Relatedly, a flow-log FV that flushes conntrack inside a retry loop against a
node carrying a HostEndpoint will provoke real, correctly-reported denies of
Felix's own control-plane traffic, because its ephemeral ports are not on a
failsafe list. That traffic is not noise to be filtered at the source; the
test's flow selection has to be narrow enough not to admit it.

### Review notes

- Prefer unit tests over FV for aggregation-state changes; the FV cannot
  distinguish "not reported yet" from "reported wrong".
- A test that asserts an exact statistic must state which aggregation level it
  assumes, and must not assume the count of connections it generated equals
  `NumFlowsStarted`.

## Keep this in sync

Update this document when any of the following changes:

- the set or meaning of the four `flowReferences` tuple sets, or anything
  else that alters `numFlows*` semantics;
- the report/expire lifecycle in `collector.go` — the timers, the three
  report paths, or the `Reported` gating;
- `AggregationKind` levels, how the level is chosen, the `FlowMeta` key
  composition, or `calibrateFlowStore`'s retention and GC rules;
- the dispatcher set or the flush interval;
- the event-source wiring for either dataplane, including expiry criteria;
- the `metric.Update` contract between stages.

Exemptions are the repo-wide ones (bug fix restoring documented behaviour,
mechanical refactor, comment or log-message edits, dependency bumps).
