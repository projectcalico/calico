---
applyTo:
  - "libcalico-go/lib/backend/api/**"
  - "libcalico-go/lib/backend/watchersyncer/**"
  - "libcalico-go/lib/backend/syncersv1/**"
  - "typha/pkg/syncclient/**"
  - "typha/pkg/syncclientutils/**"
  - "typha/pkg/calc/**"
  - "felix/calc/validation_filter.go"
  - "felix/calc/async_decoupler.go"
  - "felix/calc/async_calc_graph.go"
  - "felix/calc/stats_collector.go"
---

# Syncer API

The Syncer API's contract — the callback interface, the consumer
algorithm, the eventual-consistency guarantees, and review
criteria — lives in the cross-component design
[`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md). The
API is consumed by Felix's calc graph, confd, the `node` helpers,
kube-controllers and the apiserver, and is fanned out over the
network by Typha, so the
design lives at the repo level rather than under any one
component.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Read [`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md)
   and apply its review notes.
2. A change to the API's guarantees affects every consumer *and*
   the Typha protocol
   ([`typha/DESIGN.md`](../../typha/DESIGN.md)); the consumer
   side in Felix is
   [`felix/design/calc-graph.md`](../../felix/design/calc-graph.md)
   ("The upstream (syncer) contract").

## Doc update rule

The repo-wide rule
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) applies;
**the default is no edit**. For the syncer the usual candidates for
it are a change to the interfaces or semantics in
`libcalico-go/lib/backend/api`, to the `watchersyncer` machinery's
guarantees, to the syncersv1 syncer/consumer pairings, or to the
dedupebuffer's contract — candidates, not triggers on their own. A
warranted edit goes in
[`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md) in the
same PR.
