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

Architecture, invariants, and review criteria for Felix's non-BPF
Linux dataplane — the manager/driver layering, the
`OnUpdate`/`apply()` event loop, the restart-and-resync
(mark-and-sweep) doctrine, the `*tables` Table abstraction, IP
sets, dispatch chains, mark bits, and the route drivers — live in
[`felix/design/dataplane.md`](../../felix/design/dataplane.md),
indexed from [`felix/DESIGN.md`](../../felix/DESIGN.md). Review
notes are embedded inline at the end of each section.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Read the relevant section(s) of
   [`dataplane.md`](../../felix/design/dataplane.md) and apply the
   review notes embedded there.
2. **The headline question for any change that creates kernel
   state:** how does a freshly-restarted Felix (no memory, possibly
   a different datastore, no delete event) recognise this resource
   as Calico's, to sweep the orphans? See "Restart, resync and
   mark-and-sweep".
3. Other recurring checks: no kernel work in `OnUpdate` (defer to
   `CompleteDeferredWork`); preserve the IP-set ordering invariant
   (create before `*tables`, delete after) across **both** the calc
   graph flush order and `apply()`; decide the iptables/nftables
   parity story explicitly; apply changes symmetrically to the IPv4
   and IPv6 instances.
4. BPF-dataplane files have their own design family — start at
   [`bpf-overview.md`](../../felix/design/bpf-overview.md). Some
   shared code (e.g. parts of `felix/rules/`) is matched by both;
   load both designs when a PR spans them.

The input boundary is the protobuf contract documented in
[`dataplane.md` → The dataplane API](../../felix/design/dataplane.md)
and from the producer side in
[`calc-graph.md`](../../felix/design/calc-graph.md). Follow links —
the design is a graph.

## Update rule

A dataplane PR that **changes how it works** — a new manager or
driver, or a change to the manager/driver split; a change to the
`apply()` ordering or the `OnUpdate`/`CompleteDeferredWork`
contract; a new kind of kernel resource or a change to how Calico
resources are identified for resync; a change to `*tables` Table
reconciliation, dispatch-chain structure, mark-bit allocation,
IP-set ordering, or route ownership classification; or a change to
the `proto.*` dataplane API — must update the relevant section of
[`dataplane.md`](../../felix/design/dataplane.md) in the same PR
(and `calc-graph.md` if the proto contract changes).

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
section and the new behaviour or invariant, for example:

> `@copilot update felix/design/dataplane.md "How each subsystem identifies \"ours\"" to cover how the new fooManager recognises its kernel resources on restart, and what it sweeps.`

The reviewer (or author) drops that into a new PR comment; the
Copilot coding agent picks it up and pushes a commit with the
amendment to the PR branch.
