---
applyTo:
  - "libcalico-go/lib/backend/api/**"
  - "libcalico-go/lib/backend/watchersyncer/**"
  - "libcalico-go/lib/backend/syncersv1/**"
---

# Syncer API

The Syncer API's contract — the callback interface, the consumer
algorithm, the eventual-consistency guarantees, and review
criteria — lives in the cross-component design
[`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md). The
API is consumed by Felix's calc graph, confd, and the `node`
helpers, and is fanned out over the network by Typha, so the
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

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply.
For the syncer, "changes how it works" means: a change to the
interfaces or semantics in `libcalico-go/lib/backend/api`, to the
`watchersyncer` machinery's guarantees, to the syncersv1
syncer/consumer pairings, or to the dedupebuffer's contract.
Update [`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md)
in the same PR.
