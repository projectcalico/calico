---
applyTo:
  - "felix/collector/**"
  - "felix/fv/flowlogs/**"
  - "felix/fv/flow_logs*_test.go"
---

# Felix flow-log collector

Architecture, invariants, and review criteria for the Felix collector —
the pipeline that turns dataplane events into flow logs — live in
[`felix/design/flow-logs-collector.md`](../../felix/design/flow-logs-collector.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). Review notes are
embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR (Copilot
code review) in any file matched by this instruction's `applyTo`:

1. Read the relevant section(s) of
   [`flow-logs-collector.md`](../../felix/design/flow-logs-collector.md)
   and apply the review notes embedded there.
2. Pay particular attention to the accounting contract: `NumFlowsStarted`
   counts flow starts **per tuple per flush interval while the flow was
   active**, not per TCP connection. Any code or test asserting an exact
   connection count against it is wrong. The design explains why —
   `FlowStats.reset` keeps `flowsRefsActive` while `calibrateFlowStore`
   deletes the bucket once it is empty, so a late `Report` for an
   already-expired tuple counts a second start.
3. A new field in `FlowReportedStats` must be handled in **both**
   `FlowReportedStats.Add` and `FlowStats.reset`.
4. For FV changes, note that `FlowTester`'s include filters are OR'd, so
   "reporter X *and* port Y" is inexpressible; a reporter-only filter
   admits host-network flows and any admitted-but-unchecked flow fails
   the test.
5. The BPF and iptables/nftables paths feed the collector through
   different transports but must produce equivalent `metric.Update`s; a
   new field needs populating on both.

Follow links — the design references siblings (notably
[`goldmane/DESIGN.md`](../../goldmane/DESIGN.md) for the downstream
aggregator), code, and external resources.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md))
apply. For the collector, "changes how it works" means: the meaning of
any of the four `flowReferences` tuple sets or anything else altering
`numFlows*` semantics; the report/expire lifecycle (timers, the three
report paths, the `Reported` gating); `AggregationKind` levels, how the
level is chosen, `FlowMeta` key composition, or `calibrateFlowStore`
retention and GC; the dispatcher set or flush interval; the event-source
wiring or its expiry criteria; or the `metric.Update` contract between
stages. Update the relevant section of
[`flow-logs-collector.md`](../../felix/design/flow-logs-collector.md) in
the same PR.
