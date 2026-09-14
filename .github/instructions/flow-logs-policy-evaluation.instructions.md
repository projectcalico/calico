---
applyTo:
  - "felix/collector/collector.go"
  - "app-policy/checker/**"
  - "app-policy/policystore/**"
  - "app-policy/policyscale/**"
---

# Flow-log collector: pending-policy evaluation

Architecture, invariants, the benchmark definition and review criteria
for the pending-policy evaluation path live in
[`felix/design/flow-logs-policy-evaluation.md`](../../felix/design/flow-logs-policy-evaluation.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md).

Before writing code (Copilot coding agent) or reviewing a PR (Copilot
code review) in any file matched by this instruction's `applyTo`:

1. Read the relevant section(s) of
   [`flow-logs-policy-evaluation.md`](../../felix/design/flow-logs-policy-evaluation.md)
   and apply the review criteria in "Common failure modes".
2. Pay particular attention to: the single-owner rule for `epStats` and
   `Data` (no goroutine but the collector's main loop touches a `Data`
   field); every store mutation goes through `ProcessUpdate` or bumps
   `Generation`; a failed evaluation keeps the previous trace; any new
   evaluator, cache or compiled path runs through the differential
   corpus and the named cases (`assertEquivalent`, `runNamedCases`)
   before it is switched on; a benchmark asserts the walk it claims
   before its timed loop, and the three egress cases are reported
   together, never one as "the" number.
3. The work ships to every active release branch: no new `v3` API
   fields on release branches, every optimisation behind a switch with
   a per-branch default, and today's single-goroutine path kept
   reachable.
4. `app-policy/checker` and `app-policy/policystore` are shared with
   Dikastes; a change that is only safe for L4-only flows must say so
   and gate on it, as the verdict cache does.

Follow links — the design references siblings, code, and the
benchmarks.
