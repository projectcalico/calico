---
applyTo:
  - "felix/calc/**"
  - "felix/labelindex/**"
  - "felix/dispatcher/**"
---

# Felix calculation graph

Architecture, invariants, and review criteria for Felix's
calculation graph live in
[`felix/design/calc-graph.md`](../../felix/design/calc-graph.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). Review
notes are embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Read the relevant section(s) of
   [`calc-graph.md`](../../felix/design/calc-graph.md) and apply
   the review notes embedded there. The `labelindex` and
   `dispatcher` packages are part of the calc graph for these
   purposes.
2. Pay particular attention to the core node invariant (output
   depends only on current datastore state — never buffer "last
   good" output across an inconsistency), the rule that index
   add/remove must be balanced and identically keyed, and the
   requirement to add **calc-graph FV tests**
   (`calc/calc_graph_fv_test.go`) rather than only per-node unit
   tests.
3. The output boundary is the protobuf contract documented from
   the consumer side in
   [`dataplane.md`](../../felix/design/dataplane.md); follow that
   link when a change affects what the graph emits or in what
   order.

Follow links — the design references siblings, code, and external
resources.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply.
For the calc graph, "changes how it works" means: a new calculation
node or rewiring; a new emitted message type or a change to the
`EventSequencer` flush order; a change to a label index or other
refcounting structure; or a change to how the graph treats
inconsistency, in-sync, or the upstream contract. Update the
relevant section of
[`calc-graph.md`](../../felix/design/calc-graph.md) in the same PR
(and `dataplane.md` if the output contract changes), and update the
hand-maintained node diagram in
[`felix/docs/calc-graph-diagram.md`](../../felix/docs/calc-graph-diagram.md)
when you add or rewire a node.
