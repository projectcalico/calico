---
applyTo:
  - "felix/calc/**"
  - "felix/labelindex/**"
  - "felix/dispatcher/**"
---

# Felix calculation graph

Architecture, invariants, and review criteria for Felix's
calculation graph (the "brain") live in
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
2. Pay particular attention to the **memoryless** node invariant
   (output is a pure function of current datastore state — never
   buffer "last good" output across an inconsistency), the
   edge-triggered/identically-keyed refcounting rule, and the
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

## Update rule

A calc-graph PR that **changes how it works** — a new calculation
node or rewiring; a new emitted message type or a change to the
`EventSequencer` flush order; a change to a label index or other
refcounting structure; a change to how the graph treats
inconsistency, in-sync, or the upstream contract — must update the
relevant section of
[`calc-graph.md`](../../felix/design/calc-graph.md) in the same PR
(and `dataplane.md` if the output contract changes).

**Exemption.** No doc update is needed if the PR is exclusively
one of: (a) a bug fix that restores behaviour the doc already
describes, (b) a mechanical refactor with no observable change,
(c) comment / log-message edits, (d) a dependency bump. If in
doubt, update the doc.

## Amending the PR

The Copilot automated code-review step is read-only with respect
to the PR branch — it cannot push the doc amendment itself. When
the review flags a missing update per the rule above, its comment
should include a ready-to-paste `@copilot` prompt naming the
section and the new behaviour or invariant, for example:

> `@copilot update felix/design/calc-graph.md "The EventSequencer (output stage)" to cover the new emitted message proto.FooUpdate — its place in the flush order, what it depends on, and what depends on it.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
