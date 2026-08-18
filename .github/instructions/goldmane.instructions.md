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

[`design/MAINTAINING.md`](../../design/MAINTAINING.md) is the
canonical rule. **The default is no edit**, and an edit that does
belong is normally one to three lines in a section that is
already there.

In goldmane, the changes that *usually* earn one are a change to
gRPC service shape or behaviour, data flow, retention or eviction
logic, the configuration surface, or the Prometheus metric set.
Treat that list as candidates, not as a trigger: the edit is
warranted only if a sentence in `goldmane/DESIGN.md` is now
false, or the change introduces an invariant or a concept the doc
does not name.

**Exemption.** No doc update at all if the PR is exclusively one
of: (a) a bug fix that restores behaviour the doc already
describes, (b) a mechanical refactor with no observable change,
(c) comment / log-message edits, (d) a dependency bump.

## Amending the PR

The Copilot automated code-review step is read-only with respect
to the PR branch — it cannot push the doc amendment itself. When
the review flags a missing update per the rule above, its comment
should include a ready-to-paste `@copilot` prompt naming the
section and the one invariant or fact to state — not a list of
details to describe. For example:

> `@copilot update goldmane/DESIGN.md "Prometheus metrics": add the new histogram goldmane_flow_age_seconds to the existing metric list in one line. Do not add a heading, and do not restate the commit message.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
