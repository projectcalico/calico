---
applyTo:
  - "felix/dataplane/linux/bpf_ep_mgr.go"
  - "felix/dataplane/linux/dataplanedefs/dataplane_defs.go"
  - "felix/bpf-gpl/fib_co_re.h"
---

# eBPF dataplane: bpf-host-networking

The design and review criteria for this area of the Calico
eBPF dataplane live in
[`felix/design/bpf-host-networking.md`](../../felix/design/bpf-host-networking.md). The
review notes are embedded inline at the end of each section.
Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`, read the relevant section(s) of
`bpf-host-networking.md` and apply those review notes.

Always also read
[`felix/design/bpf-overview.md`](../../felix/design/bpf-overview.md)
for the packet-path mental model, fast-path cost rule, and
cross-cutting review rules. The whole BPF design is a graph;
load whichever sub-designs are matched by the paths your PR
touches (see
[`felix/DESIGN.md`](../../felix/DESIGN.md) for the full
table).

## Update rule

A BPF dataplane PR that **changes how the dataplane works** in
the area covered by this instructions file must update the
relevant section in the linked sub-design (and the `bpf-overview`
file, if cross-cutting content is affected) in the same PR.

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
