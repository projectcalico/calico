---
applyTo:
  - "libcalico-go/lib/ipam/**"
  - "libcalico-go/lib/backend/**/ipam*"
  - "libcalico-go/lib/backend/**/block_affinity*"
  - "cni-plugin/pkg/ipamplugin/**"
  - "cni-plugin/pkg/k8s/**"
  - "node/cmd/calico-ipam/**"
  - "node/pkg/allocateip/**"
  - "kube-controllers/pkg/controllers/node/ipam*.go"
  - "kube-controllers/pkg/controllers/node/pool_manager.go"
  - "kube-controllers/pkg/controllers/node/ipam_allocation.go"
  - "kube-controllers/pkg/controllers/loadbalancer/**"
  - "kube-controllers/pkg/controllers/flannelmigration/**"
  - "calicoctl/calicoctl/commands/ipam/**"
  - "calicoctl/calicoctl/commands/datastore/migrate/**"
---

# IPAM

Architecture, invariants, data model, allocation flow, GC
behavior, and per-section review criteria for Calico IPAM live
under [`design/ipam/`](../../design/ipam/), indexed by
[`design/ipam/DESIGN.md`](../../design/ipam/DESIGN.md).
IPAM is cross-component (`libcalico-go/lib/ipam`, `cni-plugin`,
`kube-controllers`, `node`, plus read-only callers like Felix and
`calicoctl`), so the design lives at the repo level rather than
under any one component. Each sub-design carries an `applies to`
glob.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`, read the index and the sub-design(s) whose `applies
to` glob matches the paths you're touching, and apply the review
notes embedded there. Follow links - the design references
siblings, code, and external resources.

## Update rule

A PR that **changes how IPAM works** - the data model, the
allocation or release flow, the handle ID convention, the GC
reconciliation logic, the `IPAMConfig` resolution rules, or any
invariant a sub-design records - must update the relevant file
under `design/ipam/` in the same PR.

**Exemption.** No doc update is needed if the PR is exclusively
one of: (a) a bug fix that restores behavior the doc already
describes, (b) a mechanical refactor with no observable change,
(c) comment / log-message edits, (d) a dependency bump. If in
doubt, update the doc.

## Amending the PR

The Copilot automated code-review step is read-only with respect
to the PR branch - it cannot push the doc amendment itself. When
the review flags a missing update per the rule above, its
comment should include a ready-to-paste `@copilot` prompt naming
the sub-design and the new behavior or invariant, for example:

> `@copilot update design/ipam/ipam-gc.md "Reconciliation" to cover the new confirmation-pass step before releasing a suspected leaked allocation - what triggers it, what it checks, and how it interacts with the existing grace period.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
