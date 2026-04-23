---
applyTo:
  - "felix/bpf-gpl/**"
  - "felix/bpf/**"
  - "felix/dataplane/linux/bpf_*.go"
  - "felix/dataplane/linux/vxlan_mgr.go"
  - "felix/design/bpf-dataplane.md"
---

# eBPF dataplane — review & write-time rules

The design and review criteria for the Calico eBPF dataplane live in
[`felix/design/bpf-dataplane.md`](../../felix/design/bpf-dataplane.md).
Each topic section in that file ends with a **Review notes** block
listing the invariants a change in that area must respect. Before
writing code (Copilot coding agent) or reviewing a PR (Copilot code
review) in any file matched by this instruction's `applyTo`, read
the relevant section(s) of `bpf-dataplane.md` and apply those
Review notes. That doc is the source of truth — do not restate its
principles here; always follow the link.

Follow links. The design may reference other sub-designs under
[`felix/design/`](../../felix/design/), other docs, or specific
code. A design is a graph; load the nodes that apply to the paths
you're touching. For the Felix sub-design index see
[`felix/DESIGN.md`](../../felix/DESIGN.md).

## Update rule

A BPF dataplane PR that **changes how the dataplane works** must
update `felix/design/bpf-dataplane.md` in the same PR: a new BPF
sub-program, CT flag, skb-mark bit, BPF map or map field, config
knob affecting any of those, or any change to the packet path or
forwarding decision.

**Exemption.** No doc update is needed if the PR is exclusively
one of: (a) a bug fix that restores behaviour `bpf-dataplane.md`
already describes, (b) a mechanical refactor with no observable
change, (c) comment / log-message edits, (d) a dependency bump.
If in doubt, update the doc.

## Amending the PR

The Copilot automated code-review step is read-only with respect
to the PR branch — it cannot push the doc amendment itself. When
the review flags a missing update per the rule above, its comment
should include a ready-to-paste `@copilot` prompt naming the
section and the new invariant / mechanic:

> `@copilot update felix/design/bpf-dataplane.md §13 to cover the new CT flag CALI_CT_FLAG_FOO — the fields it uses, where it is set, how it interacts with the fast path.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch. Pre-formatting the invocation in the
review comment is the path of least resistance — without it the
doc drift typically ends up in a follow-up PR.
