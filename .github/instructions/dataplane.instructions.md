---
applyTo:
  - "felix/iptables/**"
  - "felix/nftables/**"
  - "felix/generictables/**"
  - "felix/ipsets/**"
  - "felix/markbits/**"
  - "felix/rules/**"
  - "felix/routetable/**"
  - "felix/routerule/**"
  - "felix/vxlanfdb/**"
  - "felix/dataplane/linux/**"
---

# Felix Linux dataplane

Architecture, invariants, and review criteria for Felix's Linux
dataplane live in
[`felix/design/dataplane.md`](../../felix/design/dataplane.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). It covers
the architecture **shared by all three modes** (iptables, nftables
and eBPF — one `InternalDataplane` codebase): the manager/driver
layering, the `OnUpdate`/`apply()` event loop, the restart-and-resync
(mark-and-sweep) doctrine, fail-closed behaviour, dual-stack and
status reporting; plus the `*tables`-specific Table abstraction, IP
sets, dispatch chains, mark bits, and route drivers. Review notes are
embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Read the relevant section(s) of
   [`dataplane.md`](../../felix/design/dataplane.md) and apply the
   review notes embedded there.
2. Beyond programming the correct corresponding kernel state, a key
   question for any change that creates kernel state: how does a
   freshly-restarted Felix (no memory, possibly a different datastore,
   no delete event) recognise this resource as Calico's, to sweep the
   orphans? See "Restart, resync and mark-and-sweep".
3. Other recurring checks: no kernel work in `OnUpdate` (defer to
   `CompleteDeferredWork`); preserve the IP-set ordering invariant
   (create before `*tables`, delete after) across **both** the calc
   graph flush order and `apply()`; decide the iptables/nftables
   parity story explicitly; apply changes symmetrically to the IPv4
   and IPv6 instances.
4. eBPF is a *mode* of this same dataplane, not a separate program:
   it reuses the shared loop/manager/resync architecture documented
   here, and adds its own packet path, BPF maps and managers in the
   `bpf-*` family (start at
   [`bpf-overview.md`](../../felix/design/bpf-overview.md)). Shared
   files (the `InternalDataplane` loop in `felix/dataplane/linux/`,
   `felix/rules/`) are matched by both this rule and the `bpf-*`
   rules — a BPF PR should load **both** this doc and the relevant
   `bpf-*` sub-designs.

The input boundary is the protobuf contract documented in
[`dataplane.md` → The dataplane API](../../felix/design/dataplane.md)
and from the producer side in
[`calc-graph.md`](../../felix/design/calc-graph.md). Follow links —
the design is a graph.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply.
For the Linux dataplane, "changes how it works" means: a new manager
or driver, or a change to the manager/driver split; a change to the
`apply()` ordering or the `OnUpdate`/`CompleteDeferredWork`
contract; a new kind of kernel resource or a change to how Calico
resources are identified for resync; a change to `*tables` Table
reconciliation, dispatch-chain structure, mark-bit allocation,
IP-set ordering, or route ownership classification; or a change to
the `proto.*` dataplane API. Update the relevant section of
[`dataplane.md`](../../felix/design/dataplane.md) in the same PR
(and `calc-graph.md` if the proto contract changes).
