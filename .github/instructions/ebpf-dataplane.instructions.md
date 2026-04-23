---
applyTo:
  - "felix/bpf-gpl/**"
  - "felix/bpf/**"
  - "felix/dataplane/linux/bpf_*.go"
  - "felix/dataplane/linux/vxlan_mgr.go"
  - "felix/design/bpf-dataplane.md"
---

# eBPF dataplane review instructions

The authoritative design and review guide for Calico's eBPF dataplane
is [`felix/design/bpf-dataplane.md`](../../felix/design/bpf-dataplane.md). Each of its
topic sections ends with a **Review notes** block listing the
invariants a change in that area must respect. When reviewing a
change that touches a file matching this instruction's `applyTo`,
cross-check the relevant section(s) of `DESIGN.md` — the doc is the
source of truth for dataplane principles; this file is a short
pointer.

## Must-check principles

- **Per-packet cost (§22).** For every BPF dataplane change,
  answer explicitly: *does this cause more packets to do more
  work?* The obvious case is new code on the fast path. The
  non-obvious case is a change that **shrinks the set of packets
  eligible for an existing fast-path shortcut** — work that
  already existed is now paid by more flows. Both need the same
  justification: a benchmark, a scoping mechanism that restores
  the shortcut in steady state, or an argument that the affected
  flow class is small. If the answer to the question is "yes" and
  the PR description doesn't address it, that's a finding. See
  §22 for cost tiers and patterns to prefer (CT flags, skb marks,
  compile-time gates, slow-path sub-programs).
- **Map versioning (§23).** Bump `MapParameters.Version` only when
  the change makes new BPF programs incompatible with the old
  pinned map. Repurposing padding / reserved bytes does not need
  a bump. Moving fields, widening keys, shrinking values, or
  depending on a field old programs write as zero does.
- **New BPF sub-programs.** Must be registered in
  `felix/bpf-gpl/jump.h` (`enum cali_jump_index`, with matching
  `_DEBUG` variant), in `felix/bpf/hook/map.go`
  (`SubProg*` constant + entry in `tcSubProgNames` /
  `xdpSubProgNames`), and filtered by `GetApplicableSubProgs`
  if they aren't needed for every attach type.
- **skb marks.** New signals between BPF and `*tables` use bits in
  `0x1FF00000` (`enum calico_skb_mark` in
  `felix/bpf-gpl/bpf.h`). Matching `*tables` rule-generator
  updates under `felix/rules/` are required when the signal
  crosses the boundary.
- **CT flags are preferred over main-path lookups.** When a check
  produces a per-flow result, encode it as a `CALI_CT_FLAG_*` at
  flow creation; the fast path reads the flag, not a map.
- **Attach-gap.** Any change that lets BPF forward a packet that
  used to go through `*tables` must consult `fib_approve` (or an
  equivalent check against the `cali_iface` readiness flag) for
  the target interface.
- **Cross-section invariants.** RPF (§12), mid-flow fallthrough
  (§16), SkipFIB for third-party DNAT (§17), bpfnat RPF sysctls
  (§10), VXLAN flow-mode device (§11), and fast-path discipline
  (§22) all have explicit rules in their Review notes sections.
  If the change touches any of those areas, read the relevant
  Review notes.

## The update rule

A BPF dataplane PR that **changes how the dataplane works** must
update `felix/design/bpf-dataplane.md` in the same PR. This includes:

- A new BPF sub-program or tail-call target.
- A new CT flag or reuse of an existing one for a new purpose.
- A new skb-mark bit or a changed meaning.
- A new BPF map, new map field, or a layout change.
- A new config knob that affects any of the above.
- Any change to the packet path, forwarding decision, or
  fast-path/slow-path split.

**Exemption.** No `DESIGN.md` update is needed if the PR is
exclusively one of:

- (a) A bug fix that restores behaviour `DESIGN.md` already
  describes.
- (b) A mechanical refactor with no observable change.
- (c) Comment / log-message edits.
- (d) Dependency bumps.

If in doubt, update the doc. A PR that modifies the BPF dataplane
without a `DESIGN.md` update and without falling into one of the
four exemptions is incomplete.

**Amending the PR.** The Copilot automated code-review step is
read-only with respect to the PR branch — it cannot push the
`DESIGN.md` amendment itself. When the review flags a missing
update per the rule above, its comment should include a
ready-to-paste `@copilot` prompt that specifies which section
needs updating and what new invariant or mechanic to cover, for
example:

> `@copilot update felix/design/bpf-dataplane.md §13 to cover the new CT flag CALI_CT_FLAG_FOO — the fields it uses, where it is set, how it interacts with the fast path.`

The reviewer (or the PR author) drops that into a new PR comment
to invoke the Copilot coding agent, which pushes a commit with
the amendment to the PR branch. Pre-formatting the invocation in
the review comment is the path of least resistance; without it
the reviewer has to draft the prompt themselves and the doc
drift typically ends up in a follow-up PR.
