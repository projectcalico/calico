<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->


# eBPF dataplane — Overview

This file is the always-pulled overview of Calico's eBPF
dataplane: the packet-path mental model, the fast-path performance
discipline, and the cross-cutting review notes that apply to every
BPF change. Per-area design content (TC program layout, XDP,
service NAT, conntrack, encapsulation, observability, and so on)
lives in sibling files under [`felix/design/`](../) — see
[`felix/DESIGN.md`](../DESIGN.md) for the full sub-design index
and the path-to-doc mapping.

If you are editing BPF dataplane code or reviewing a BPF dataplane
PR, read this file plus whichever sibling sub-designs match the
paths the change touches. The Copilot path-scoped instruction
files in [`.github/instructions/`](../../.github/instructions/) do
this matching automatically; humans should consult
`felix/DESIGN.md`'s table.

## Conventions used in BPF design docs

- `*tables` means "the legacy netfilter dataplane, iptables or
  nftables", i.e. any non-BPF Linux dataplane Felix can program.
  Where a statement is specific to one backend, the backend is
  named.
- "WEP" = workload endpoint (a `cali*` veth on the host side, with
  a pod on the other side). "HEP" = host endpoint (a physical or
  tunnel interface the cluster administrator has put under policy).
  Felix treats a small number of special interfaces (the main
  route interface, tunnel devices, the `bpfnat` veth pair) as
  HEP-like even when no HostEndpoint CRD exists.
- BPF programs live in the **host namespace** and these docs
  reason about all packet directions from the host namespace's
  point of view. "Host-ingress" = a packet entering the host
  namespace; "host-egress" = a packet leaving it. For a WEP these
  are the _reverse_ of the pod's policy direction (Calico's
  "ingress policy" for a pod is implemented on the host-egress
  side of the `cali*` veth).
- File paths are repo-relative. Only file paths, function names,
  struct names, map names and constants are cited — line numbers
  are deliberately omitted because they rot.

## Packet path overview

### Where programs are attached

Felix attaches TC BPF programs to every interface it cares about on the
host:

- Every workload veth on the host side (`cali*`), both host-ingress
  (TC ingress hook — a packet coming from the pod, policy-egress from
  the pod's point of view) and host-egress (TC egress hook — a packet
  going to the pod, policy-ingress).
- Host endpoints — the interfaces matching the
  `BPFDataIfacePattern` regex. At minimum the node's main cluster
  interface is included; any interface the cluster admin has put under
  HEP policy is too.
- Tunnel interfaces Calico owns: IPIP, VXLAN, WireGuard.
- The `bpfnat` veth pair (see [bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md)) and the loopback device, which Felix
  programs as HEP-like even when the admin hasn't defined a
  HostEndpoint for them.

XDP programs are attached earlier in the receive path on HEPs that
support XDP; they carry untracked policy and can fast-drop hostile
traffic before it reaches TC. Connect-time load-balancer programs
([bpf-services.md → Connect-Time Load Balancer (CTLB)](./bpf-services.md)) are attached to cgroup hooks rather than interfaces.

### Where BPF sits relative to netfilter

On host-ingress (a packet arriving on an interface) the TC ingress
hook runs **before** netfilter. On host-egress (a packet leaving an
interface) the TC egress hook runs **after** netfilter. BPF
therefore sees the packet before `*tables` on the way in and after
`*tables` on the way out, so it can overrule netfilter on ingress
and see netfilter's output on egress.

The practical consequence is that BPF can bypass the host network
stack completely when it has enough information to forward directly.
A packet forwarded via `bpf_redirect`, `bpf_redirect_neigh`, or
`bpf_redirect_peer` skips the host's routing, conntrack and
iptables/nftables chains entirely. `bpf_redirect_peer` goes a step
further: on a veth destination it hands the packet straight to the
pod side without running the program attached to the host-side peer,
which is the usual way into a local workload on the fast path.

### When BPF defers to the host stack

BPF does not try to handle every case. It hands packets to the host
stack (or lets them continue through it) when it cannot:

- **FIB lookup miss.** If `bpf_fib_lookup` fails, BPF lets the kernel
  route the packet so the kernel can populate its FIB and neigh
  caches; subsequent packets of the same flow can then be forwarded
  directly. This case used to be frequent because `bpf_fib_lookup`
  returned `NO_NEIGH` whenever the neigh cache was cold, forcing a
  host-stack detour even when the route was known. Since Calico's
  minimum kernel is 5.10 the `bpf_redirect_neigh` helper is always
  available and BPF resolves the neighbour itself on the fast path,
  so the host-stack detour is now the exception.
- **SNAT / MASQUERADE (`nat-outgoing`).** Full port-preserving SNAT
  requires port allocation state that BPF cannot safely produce; the
  `*tables` SNAT chain handles it. BPF signals this path by marking the
  packet (`CALI_SKB_MARK_NAT_OUT` / `CALI_SKB_MARK_MASQ`).
- **Pre-existing connections.** Connections established before BPF was
  loaded have no BPF conntrack entry. Rather than dropping them, BPF
  marks them `CALI_SKB_MARK_FALLTHROUGH` and lets `*tables` CT match
  against its own entry; see [bpf-conntrack-flowstate.md → Switching from `*tables` to eBPF](./bpf-conntrack-flowstate.md).
- **Third-party DNAT rules.** Some deployments rely on DNAT rules that
  another agent installed in the `*tables` raw/nat chain. BPF
  cooperates via the `SKIP_FIB` mark; see [bpf-conntrack-flowstate.md → 3rd-party DNAT on host traffic](./bpf-conntrack-flowstate.md).
- **Host-originated traffic _to services_.** Not strictly "deferring"
  — the `bpfnat` veth routes these packets back through BPF after
  `*tables` has had a chance to MASQUERADE them; see [bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md). This only
  applies to service traffic; host-originated traffic whose endpoint
  is in the host namespace (host-networked peer, host-local socket)
  obviously cannot skip the host stack and does not use this path.

When BPF _can_ answer the question — FIB hit, known local pod, existing
BPF conntrack entry, matched NAT frontend with an acceptable backend —
it forwards directly and the host stack never sees the packet.

### Marks: the out-of-band channel between BPF and netfilter

BPF and `*tables` communicate via the top bits of the skb mark. The
full table is in `felix/bpf-gpl/bpf.h` (`enum calico_skb_mark`); the
marks a reviewer encounters most often are:

| Mark                          | Set by            | Meaning                                                            |
| ----------------------------- | ----------------- | ------------------------------------------------------------------ |
| `CALI_SKB_MARK_SEEN`          | Any BPF program   | At least one BPF program has already processed this packet.       |
| `CALI_SKB_MARK_BYPASS`        | BPF after policy  | Packet is approved; downstream BPF does not need to re-validate.   |
| `CALI_SKB_MARK_FALLTHROUGH`   | BPF on host ingress | No BPF CT entry — let `*tables` decide based on its CT state.    |
| `CALI_SKB_MARK_CT_ESTABLISHED`| `*tables` rule    | `*tables` CT saw this as part of an established flow.             |
| `CALI_SKB_MARK_SKIP_FIB`      | BPF or `*tables`  | Do not run the BPF FIB lookup; hand the packet to the host stack. |
| `CALI_SKB_MARK_NAT_OUT` / `CALI_SKB_MARK_MASQ` | BPF | Flow needs SNAT; iptables MASQUERADE will handle it.    |
| `CALI_SKB_MARK_FROM_NAT_IFACE_OUT` | BPF on `bpfnatout` egress | Packet has passed through the host-networking workaround veth. |

Felix reserves the top three nibbles of the mark (`0x1FF00000`) for BPF
use. `IptablesMarkMask` must include this range and leave room for any
non-BPF `*tables` rules; Felix refuses to start if it does not.

### Review notes for this section

- A PR that adds a new out-of-band signal between BPF and `*tables`
  needs a bit in `enum calico_skb_mark` and, if `*tables` has to set
  or match it, a matching change in the rule generators under
  `felix/rules/` (and the nftables variant if applicable). The mark
  must also fit inside the reserved mask.
- A PR that makes BPF forward a packet directly that used to go
  through the host stack must confirm that none of the "deferral"
  reasons above apply. In particular, bypassing the kernel on a flow
  that still needs SNAT will break the return path.




## Fast-path performance discipline

### The rule

The eBPF dataplane's performance comes from keeping the per-packet
work on the **fast path** small. The fast path is everything a
packet on an established flow hits: the preamble, the main
program's conntrack lookup, a mark check or two, and (on allow)
forwarding. Work added here is paid at packet rate — on a hot link,
every extra instruction and every extra map lookup is paid millions
of times a second.

**A change that adds per-packet work to the fast path is not
acceptable without explicit justification.** The bar is higher than
for any other area of the dataplane because the fast path carries
all of the production throughput.

### Cost tiers

- **Cheap — fine on the fast path.** Mark comparisons, inline header
  validation, reads of fields already in `ctx->state` or per-CPU
  state, arithmetic on values the program already holds. These cost
  a handful of instructions and no map operation.
- **Borderline — case by case.** A single BPF map lookup. A single
  FIB or route-table lookup. Adding one to a path that already does
  several is often fine; adding one to a path that had none is
  often not. "Hot" paths (established-flow packets) should be
  looked at harder than "lukewarm" ones (first packet of a flow,
  where CT creation already dominates the cost).
- **Expensive — not on the fast path.** Multiple map lookups, a
  tail-call into another sub-program, re-running the policy
  program, hash computations (Maglev), defragmentation. These
  belong on slow paths or on flow-creation, not on every packet.

### Fast path vs slow path

Where the new work lands matters more than what it is:

- **Fast path** — every packet of an established flow. Preamble →
  main → CT lookup → (on hit) allowed/epilogue. New work here is
  presumed bad; the PR needs to make an explicit case for it.
- **Flow-creation path** — first-packet work: policy evaluation,
  NAT lookup, conntrack create. Already expensive; adding one
  lookup here is rarely the thing that regresses the dataplane.
- **Slow / error path** — ICMP error generation, fragment
  reassembly, host-CT conflict resolution, TCP reset, log filter
  compilation. These run rarely and failure is tolerable; expensive
  work here is fine.

The single most common way a PR regresses this dataplane is by
moving work from "flow-creation" to "main" — adding a check or a
lookup that looks cheap but runs on every packet instead of only
when a flow is being established. A reviewer should check whether
a new check could be gated on
`state->ct_result.rc == CALI_CT_NEW` (or an equivalent "first
packet" condition); if it could and isn't, that's a red flag.

### Patterns to prefer

- **Store the decision on the conntrack entry.** If a check
  produces a per-flow result, record it as a CT flag
  (`CALI_CT_FLAG_*` in `conntrack_types.h`) at flow creation and
  read it on the fast path. DSCP ([bpf-observability.md → QoS](./bpf-observability.md)), Maglev ([bpf-services.md → Maglev load balancer](./bpf-services.md)) and SVC_SELF
  ([bpf-services.md → Intra-cluster traffic & service NAT](./bpf-services.md)) all follow this pattern.
- **Use the skb mark between consecutive programs.** Marks are
  already in cache; reading and writing them is negligible.
- **Gate optional work on compile-time flags.** When a feature is
  off for this attach type, a `CALI_F_*` / `HAS_*` guard in
  `bpf.h` eliminates the code at verification time. A runtime
  global flag costs a load per packet — cheap but not free.
- **Own a sub-program for slow work.** When a feature does need
  real computation (Maglev hashing, fragment reassembly, ICMP
  error generation), put it in its own tail-called sub-program
  that the main program reaches only when the condition is met.

### Review notes

- A new map lookup on the main program's hot path needs an explicit
  justification in the PR description: "runs every packet; here's
  why it's cheap enough", or "gated on first-packet", or a
  benchmark.
- A new tail-call from main is a warning sign. The existing
  sub-programs (Maglev, IP-frag, ICMP, new-flow, policy) were all
  carved out because the verifier or performance told us to.
- A new CT flag plus a main-path branch is almost always
  preferable to a new main-path map lookup.
- "It's only one lookup" is not evidence. A benchmark, or a
  feature gate that keeps the cost off the default path, is.
- A change that **suppresses or narrows an existing fast-path
  shortcut** for a class of flows is the same kind of change as
  adding a per-packet map lookup — work that already existed is
  now paid by more flows. Required: a benchmark, OR a scoping
  mechanism that restores the shortcut in steady state
  (gen-counter, time-bounded flag), OR an explicit case that the
  affected flow class is small enough not to matter.




## Cross-cutting review notes

The per-section review notes cover what a reviewer should check inside
a given topic. This final section collects the handful of checks that
don't belong to any single topic — they come up repeatedly in BPF
dataplane review because several subsystems happen to share them.

### Keep this document in sync with the code

A BPF dataplane PR that changes how the dataplane works — a new
sub-program, a new CT flag, a new mark bit, a new map or map field,
a change to the packet path or forwarding decision, or a new config
knob affecting any of those — must update the relevant section of
this document in the same PR.

Exemptions: (a) a bug fix that restores behaviour this document
already describes, (b) a mechanical refactor with no observable
change, (c) comment or log-message edits, (d) dependency bumps. If
in doubt, update the doc.

This rule is mirrored in `felix/CLAUDE.md` (for Claude's `/review`
skill) and in `.github/copilot-instructions.md` plus the
path-scoped `.github/instructions/bpf.instructions.md` (for
GitHub Copilot's automated review). Those files are short
pointers; this document and its sibling sub-designs under
[`felix/design/`](.) are the source of truth.

### Changes that touch shared maps

- A change to the on-wire layout of a pinned BPF map needs a
  version bump on `MapParameters.Version` in
  `felix/bpf/.../map.go` **only when new programs are not
  compatible with the old map**. Repurposing reserved or padding
  bytes so that new programs still read and write the old map
  correctly does not require a bump — the old map is still a
  valid layout for the new programs, and old programs simply
  don't know about the new field. Changes that move fields,
  widen the key, shrink the value, or depend on a field that old
  programs write as zero *do* require a bump. The kernel refuses
  to pin two different layouts under one name, so a missed bump
  blocks upgrades; an unnecessary bump discards warm map state
  (cold conntrack, empty NAT, etc.) across the transition.
- A new map that BPF programs update from multiple CPUs
  concurrently needs a clear consistency story: spinlock (like
  `cali_qos`), per-CPU (like `cali_v4_frgtmp`), or LRU with
  idempotent semantics (like the conntrack maps). Ad-hoc
  hash-with-no-locking is almost never the right choice for
  programs that write.

### Changes that introduce new BPF sub-programs

See [bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md) for the full list. The short version: a new sub-program needs
an index enum in `jump.h`, a matching `_DEBUG` variant, a
`SubProg*` constant and symbol name in `felix/bpf/hook/map.go`, and
filtering in `GetApplicableSubProgs` if it is not universally
applicable. Forgetting any of these leaves the program un-called on
the debug path or on some attach types.

### Changes that add out-of-band signals

The top nibbles of the skb mark (`0x1FF00000`) are the BPF-owned
communication channel with `*tables`. Everything else is either
local to the BPF path (conntrack flags, per-CPU state) or
`*tables`-internal. A new signal should reuse an existing mark
bit if its semantics match, or allocate a new one — never reuse a
mark bit for a different purpose, and never put a BPF signal in a
bit outside `0x1FF00000` (Felix validates `IptablesMarkMask` at
startup and will refuse to run if the reserved range isn't
protected).

### Changes that affect whether BPF forwards or defers

Every time a packet could be forwarded directly by BPF _or_ handed
to the host stack, the decision has to consider:

- Does the flow need SNAT (`nat-outgoing`, tunnel SNAT)? If yes,
  defer — BPF cannot safely allocate source ports.
- Is there a pre-existing `*tables` CT entry? If yes, defer or
  honour the `CALI_SKB_MARK_CT_ESTABLISHED` mark.
- Is the target interface ready ([bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md))? If not, defer via
  `SKIP_FIB`.
- Is there a third-party DNAT in `*tables` the packet might need?
  If its destination is the local host, defer (`SKIP_FIB`).

A PR that "improves performance by forwarding earlier" should list
which of these it has considered.

### Changes that affect what runs under `*tables`

The `*tables` side in BPF mode is thinner than in the pure-`*tables`
dataplane — most policy is in BPF. Rules that remain are primarily:

- The pre-established flow marking rule ([bpf-conntrack-flowstate.md → Switching from `*tables` to eBPF](./bpf-conntrack-flowstate.md)).
- The SkipFIB-for-local-dest rule ([bpf-conntrack-flowstate.md → 3rd-party DNAT on host traffic](./bpf-conntrack-flowstate.md)).
- MASQ/SNAT chains for outgoing traffic.
- The attach-gap drop rules ([bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md)).
- Failsafes.

A rule added for BPF mode should be conditional on `BPFEnabled` (or
a more specific flag) and should not duplicate work that BPF already
does (policy, conntrack). If it needs to do both, there is usually
a bug.

### Kernel version sensitivity

Several BPF features depend on kernel version:

- TCX attach (kernel 6.1+) — Felix falls back to legacy TC
  classifier attach when TCX is unavailable. Changes that assume a
  specific attach type should also work under both.
- Jump maps per TCX direction (kernel 6.12+) — the split into
  `cali_progs_ing` vs `cali_progs_egr` is the workaround ([bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md)).
- `bpf_redirect_neigh` availability — [bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md)'s bpfnat turnaround falls
  back to bounce-off-the-veth when this helper isn't available.
- IP defrag sub-program (`SubProgIPFrag`) — older verifiers reject
  it; the loader retries without it ([bpf-encap-fragments-icmp.md → IP fragmentation](./bpf-encap-fragments-icmp.md)).

A PR that uses a new kernel-version-dependent helper must have a
fallback path, or the dataplane will fail to load on older kernels
Calico still supports.

