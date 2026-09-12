---
applyTo:
  - "felix/dataplane/linux/proxy_neigh_mgr.go"
  - "felix/dataplane/linux/endpoint_mgr.go"
  - "cni-plugin/pkg/dataplane/linux/dataplane_linux.go"
  - "networking-calico/networking_calico/agent/linux/dhcp.py"
---

# Neighbour discovery (proxy ARP / proxy NDP)

Architecture, invariants, and review criteria for how Calico answers
ARP and NDP live in
[`felix/design/neighbour-discovery.md`](../../felix/design/neighbour-discovery.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). It covers the
two distinct mechanisms — the workload-facing `proxy_arp` / `proxy_ndp`
sysctls and the fabric-facing userspace proxy-neighbour responder — why
the IPv4 and IPv6 stories are asymmetric, and how each interacts with
VM live migration. Review notes are embedded inline at the end of each
section.

Before writing code (Copilot coding agent) or reviewing a PR (Copilot
code review) in any file matched by this instruction's `applyTo`:

1. Read the relevant section(s) of
   [`neighbour-discovery.md`](../../felix/design/neighbour-discovery.md)
   and apply the review notes embedded there.
2. Establish **which direction** the change serves: requests from the
   local workload (sysctls, `endpoint_mgr.go`) or requests from the
   fabric (`proxy_neigh_mgr.go`). They are unrelated mechanisms and a
   fix in the wrong one will look plausible and do nothing.
3. Do not assume IPv4/IPv6 symmetry here. `proxy_ndp` does no
   route-based proxying — it answers only for explicit `NUD_PROXY`
   neighbour entries, which Calico never programs — so the IPv6 sysctl
   is inert and IPv4 proxy-ARP workarounds have no IPv6 counterpart to
   write. Symmetry *is* required of anything reached per-family through
   the endpoint managers; see the live-migration sections.
4. The live-migration interactions are asymmetric on purpose in one
   place and a documented gap in another: the ARP suppression is
   IPv4-only by design, while the fabric-facing responder's role-based
   gate is a known, deliberately deferred gap. Neither should be
   "tidied up" without reading the corresponding section.

Since much of `endpoint_mgr.go` is outside this topic, a PR touching
that file will usually need
[`dataplane.md`](../../felix/design/dataplane.md) as well. Follow links
— the design is a graph.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply. For
neighbour discovery, "changes how it works" means: a new or removed
sysctl on workload interfaces; a change to what the fabric-facing
responder answers for, where it listens, or how it selects an
answering node; a change to the live-migration ARP suppression; any
move towards programming proxy neighbour entries; or a change to the
external premises this doc rests on — the OpenStack DHCP agent's RA /
`off-link` handling, or the CNI plugin's link-local gateway. Update
[`neighbour-discovery.md`](../../felix/design/neighbour-discovery.md)
in the same PR.
