---
applyTo:
  - "goldmane/**"
---

# goldmane

Architecture, gRPC services, data flow, key concepts, configuration
surface, Prometheus metric reference, and per-section review
criteria for goldmane live in
[`goldmane/DESIGN.md`](../../goldmane/DESIGN.md). Review notes are
embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`, read the relevant section(s) of `goldmane/DESIGN.md`
and apply the review notes embedded there. Follow links — the
design references siblings, code, and external resources.

## Update rule

A goldmane PR that **changes how goldmane works** — gRPC service
shape or behaviour, data flow, retention or eviction logic, the
configuration surface, or the Prometheus metric set — must
update the relevant section of `goldmane/DESIGN.md` in the same
PR.

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

> `@copilot update goldmane/DESIGN.md "Prometheus metrics" to cover the new histogram goldmane_flow_age_seconds — the labels it carries, where it is observed, and what the buckets represent.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
