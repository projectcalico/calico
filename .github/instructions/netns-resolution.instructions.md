---
applyTo:
  - "felix/netns/**"
  - "felix/cri/**"
  - "felix/dataplane/linux/netns_mgr.go"
---

# Felix pod netns resolution

Architecture, invariants, and review criteria for Felix's pod
network-namespace resolution live in
[`felix/design/netns-resolution.md`](../../felix/design/netns-resolution.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). Review notes
are embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Read [`netns-resolution.md`](../../felix/design/netns-resolution.md)
   and apply the review notes embedded there.
2. Pay particular attention to: the execution model (Tier 1 inline,
   Tiers 2/3 on the background resolver with a single batched `/proc`
   walk — never on the main loop); the locking of `paths`/`cookies`/
   `pendingDeep` and the "still pending?" store race; the wakeup case
   that **must** set `dataplaneNeedsSync`; the `/host/proc/1/root`
   host-root mechanism with `SecureJoin` (no `hostPID` dependency); and
   that the `cni.projectcalico.org/podNetns` annotation is a trust
   anchor protected by the VAP.

Follow links — the design references siblings (`calc-graph.md`,
`dataplane.md`), code, and the operator-side companion resources.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply. For
netns resolution, "changes how it works" means: a new/changed tier or
tier ordering; a change to the execution model (what runs inline vs on
the background resolver, or the batching); a change to the host-root
mechanism; a change to the `netnsManager` query API; or a change to the
protected annotation set / VAP exemptions (which must also update the
operator's embedded copy). Update
[`netns-resolution.md`](../../felix/design/netns-resolution.md) in the
same PR.
