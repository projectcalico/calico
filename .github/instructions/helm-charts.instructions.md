---
applyTo:
  - "charts/**"
---

# Helm charts

The install and upgrade instructions users follow live in two
README files, not in a `DESIGN.md`:

- [`charts/tigera-operator/README.md`](../../charts/tigera-operator/README.md)
  — the Installing and Upgrading flows for the operator chart.
- [`charts/crd.projectcalico.org.v1/README.md`](../../charts/crd.projectcalico.org.v1/README.md)
  — install/upgrade for the separately shipped CRD chart.

These READMEs are hand-written, not generated. They drift silently
when a chart change alters the steps a user has to run but the doc
is left alone — that drift is what shipped a broken install in
v3.32 (CRDs moved to their own chart, but the operator README still
said `helm install` the operator chart directly). See #12860.

Before reviewing a PR (Copilot code review) that touches any file
matched by this instruction's `applyTo`, check whether the change
affects how a user installs or upgrades Calico via Helm, and if so
whether the two READMEs above still match. Things that change the
user-facing steps include: moving resources between charts (CRDs
especially), adding or removing a manual prerequisite step,
renaming a chart or the repo, changing the namespace handling, or
changing a documented values key or example command.

## Update rule

A chart PR that changes how a user installs or upgrades Calico via
Helm must update the matching install/upgrade instructions in the
same PR.

**Exemption.** No README update is needed if the change does not
alter any documented step — e.g. a values default that the README
never mentions, a templating-only refactor, or a generated-CRD
content bump. If in doubt, update the doc.

## Amending the PR

The Copilot automated code-review step is read-only with respect
to the PR branch — it cannot push the doc amendment itself. When
the review flags a missing update per the rule above, its comment
should include a ready-to-paste `@copilot` prompt naming the README
and the step that drifted, for example:

> `@copilot update charts/tigera-operator/README.md Installing section to cover the new CRD install step — users must apply the crd.projectcalico.org.v1 chart before installing the operator chart.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
