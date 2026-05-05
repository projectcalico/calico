---
applyTo:
  - "felix/bpf-gpl/**"
  - "felix/bpf/**"
  - "felix/dataplane/linux/bpf_*.go"
  - "felix/dataplane/linux/vxlan_mgr.go"
  - "felix/dataplane/linux/dataplanedefs/dataplane_defs.go"
  - "felix/rules/static.go"
---

# eBPF dataplane

Architecture, invariants, and review criteria for the Calico eBPF
dataplane live under
[`felix/design/bpf-*.md`](../../felix/design/), indexed by the
sub-design topic table in
[`felix/DESIGN.md`](../../felix/DESIGN.md). Review notes are
embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Open [`felix/DESIGN.md`](../../felix/DESIGN.md) and find every
   `bpf-*` row whose **applies to** glob matches a path in this
   PR. Multi-area PRs match multiple rows — load every matching
   sub-design.
2. Always also load
   [`bpf-overview.md`](../../felix/design/bpf-overview.md). It is
   the umbrella sub-design that carries the packet-path mental
   model, fast-path cost rule, and cross-cutting review notes the
   topic-specific sub-designs build on.
3. Match by **topic** as well as by path. A change described as
   "fixing the conntrack scanner" pulls
   `bpf-conntrack-flowstate.md` even when the edit lands in a
   central file the glob doesn't list narrowly.
4. Apply the review notes embedded in each section of the loaded
   sub-design(s).

The whole BPF design is a graph: sub-designs reference one another
and external resources. Follow the links.

## Update rule

A BPF dataplane PR that **changes how the dataplane works** must
update the relevant section of the matching sub-design (and
`bpf-overview.md` if cross-cutting content is affected) in the
same PR.

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
sub-design, the section, and the new invariant or mechanic, for
example:

> `@copilot update felix/design/bpf-conntrack-flowstate.md "Conntrack & cleanup" to cover the new CT flag CALI_CT_FLAG_FOO — the fields it uses, where it is set, how it interacts with the fast path.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
