---
applyTo:
  - "felix/collector/**"
---

# Felix flow-logs collector

Architecture, invariants, and review criteria for Felix's flow-logs
collector live in
[`felix/design/flow-logs-collector.md`](../../felix/design/flow-logs-collector.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). Review notes
are embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR (Copilot
code review) in any file matched by this instruction's `applyTo`:

1. Read the relevant section(s) of
   [`flow-logs-collector.md`](../../felix/design/flow-logs-collector.md)
   and apply the review notes embedded there.
2. Pay particular attention to three invariants:
   - **Single owner.** The collector `select` loop is the sole owner of
     `epStats` and of every field of every `Data`. Code that has
     another goroutine read or write them is changing the design, and
     adding a mutex to `Data` or `RuleTrace` is a design change rather
     than a fix.
   - **Copy-on-write policy slices.** A published `metric.Update`
     aliases live flow state. `rulesToReport`,
     `IngressPendingRuleIDs` and `EgressPendingRuleIDs` must be
     replaced wholesale, never mutated or reused in place. Reusing a
     slice here corrupts flow logs silently. `RuleTrace.Path()` is a
     mutating read and belongs on the owning goroutine only.
   - **Don't stall the loop.** Reader channels are finite, so a stall
     loses conntrack/NFLOG input and produces wrong byte counts, not
     merely late logs. New per-flow periodic work is an O(all flows)
     sweep and needs a time budget; a `Report` implementation must not
     block on I/O.
3. Endpoint and policy lookups come from the calc graph — see
   [`calc-graph.md`](../../felix/design/calc-graph.md). The BPF
   dataplane's counter sources are described in
   [`bpf-observability.md`](../../felix/design/bpf-observability.md).
   Follow those links when a change crosses either boundary.

Follow links — the design references siblings, code, and external
resources.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply. For
the collector, "changes how it works" means: a change to which
goroutine owns `epStats` or `Data`; a new field on `metric.Update` or a
change to what a published update aliases; a change to the reporting
gates or the expiry paths; a new or altered periodic sweep, or a change
to how one is time-boxed; or a change to where aggregation runs. Update
the relevant section of
[`flow-logs-collector.md`](../../felix/design/flow-logs-collector.md)
in the same PR.
