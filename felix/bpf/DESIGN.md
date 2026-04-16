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

# Calico eBPF Dataplane — Design & Review Guide

## Purpose

This document describes how Calico's eBPF dataplane is organised and why
it is organised that way. It is intended to serve two audiences:

- **Developers** working on the dataplane — as a map from the
  high-level design to the code that implements it.
- **Reviewers** of future dataplane PRs — as a catalogue of the
  invariants and conventions that changes in this area need to respect.

It is _not_ a tutorial on eBPF, nor a replacement for the per-package
documentation or the per-function comments in the code. It also is not a
user-facing guide: features are described as the dataplane sees them,
not as they appear in Calico CRDs or Felix config.

Where an area of the code encodes a non-obvious decision, this document
calls it out as a **review note**. Review notes are deliberately
generic: they point out what a reviewer should look for rather than
enumerating every caller.

The reference for the _principles_ behind the design is the
"eBPF Dataplane Networking" internal document. This file is the
in-tree, code-grounded counterpart to that reference.

## Scope

**In scope:**

- Linux TC, XDP and cgroup BPF programs under `felix/bpf-gpl/` and
  `felix/bpf-apache/`.
- The userspace Go code under `felix/bpf/` that loads, attaches and
  syncs those programs and their maps.
- Dataplane behaviour observable on the wire: packet path, NAT,
  conntrack, RPF, fragmentation, QoS, log filtering.
- Interaction with the legacy netfilter dataplane (referred to below as
  `*tables` — this covers both `iptables` and `nftables` backends,
  which Felix can use interchangeably for the non-BPF dataplane).
- Switching clusters from `*tables` to BPF without breaking existing
  connections.

**Out of scope:**

- Windows HNS/HCN dataplane (`felix/dataplane/windows/`).
- Pure policy model (tiers, rules, selectors) — this is produced by
  `felix/calc/` and consumed by the BPF policy program generator
  (`felix/bpf/polprog/`); this doc treats policy as an input.
- User-facing config surface — see the Felix config documentation.
- BPF build tooling — see `felix/bpf-gpl/Makefile` and
  `felix/bpf/bpfdefs/`.

## Conventions used in this document

- `*tables` means "the legacy netfilter dataplane, iptables or
  nftables", i.e. any non-BPF Linux dataplane Felix can program. Where
  a statement is specific to one backend, the backend is named.
- "WEP" = workload endpoint (a `cali*` veth on the host side, with a
  pod on the other side). "HEP" = host endpoint (a physical or tunnel
  interface the cluster administrator has put under policy). Felix
  treats a small number of special interfaces (the main route
  interface, tunnel devices, the `bpfnat` veth pair) as HEP-like even
  when no HostEndpoint CRD exists.
- "Kernel ingress"/"kernel egress" refers to the direction the kernel
  sees on the TC hook. For a WEP these are the _reverse_ of the pod's
  policy-direction ("ingress policy" is programmed on the host-side
  `cali*` egress hook, because packets from a pod enter the host on
  that hook).
- File paths are repo-relative. Only file paths, function names,
  struct names, map names and constants are cited — line numbers are
  deliberately omitted because they rot.

## Table of contents

1. [Packet path overview](#1-packet-path-overview)
2. [TC program layout](#2-tc-program-layout)
3. [Intra-cluster traffic & service NAT](#3-intra-cluster-traffic--service-nat)
4. [External traffic (NodePort, DSR)](#4-external-traffic-nodeport-dsr)
5. [Maglev load balancer](#5-maglev-load-balancer)
6. [Connect-Time Load Balancer (CTLB)](#6-connect-time-load-balancer-ctlb)
7. [Host-networked workaround (bpfnat veth)](#7-host-networked-workaround-bpfnat-veth)
8. [VXLAN in eBPF mode](#8-vxlan-in-ebpf-mode)
9. [Reverse-path filter (RPF)](#9-reverse-path-filter-rpf)
10. [Conntrack & cleanup](#10-conntrack--cleanup)
11. [IP fragmentation](#11-ip-fragmentation)
12. [Switching from `*tables` to eBPF](#12-switching-from-tables-to-ebpf)
13. [3rd-party DNAT on host traffic](#13-3rd-party-dnat-on-host-traffic)
14. [Debug log filters](#14-debug-log-filters)
15. [QoS](#15-qos)
16. [Cross-cutting review notes](#16-cross-cutting-review-notes)

---

## 1. Packet path overview

### Where programs are attached

Felix attaches TC BPF programs to every interface it cares about on the
host:

- Every workload veth on the host side (`cali*`), both kernel-ingress
  (kernel TC ingress = policy egress) and kernel-egress (policy
  ingress).
- Host endpoints — the interfaces matching the
  `BPFDataIfacePattern` regex. At minimum the node's main cluster
  interface is included; any interface the cluster admin has put under
  HEP policy is too.
- Tunnel interfaces Calico owns: IPIP, VXLAN, WireGuard.
- The `bpfnat` veth pair (see §7) and the loopback device, which Felix
  programs as HEP-like even when the admin hasn't defined a
  HostEndpoint for them.

XDP programs are attached earlier in the receive path on HEPs that
support XDP; they carry untracked policy and can fast-drop hostile
traffic before it reaches TC. Connect-time load-balancer programs
(§6) are attached to cgroup hooks rather than interfaces.

### Where BPF sits relative to netfilter

On kernel ingress (packet arriving on an interface) the TC hook runs
**before** netfilter. On kernel egress (packet leaving an interface)
the TC hook runs **after** netfilter. BPF therefore sees the packet
before `*tables` on the way in and after `*tables` on the way out, so
it can overrule netfilter on ingress and see netfilter's output on
egress.

The practical consequence is that BPF can bypass the host network
stack completely when it has enough information to forward directly.
Any packet it forwards via `bpf_redirect` or `bpf_redirect_peer`
skips the host's routing, conntrack and iptables/nftables chains
entirely.

### When BPF defers to the host stack

BPF does not try to handle every case. It hands packets to the host
stack (or lets them continue through it) when it cannot:

- **FIB lookup miss.** If `bpf_fib_lookup` fails, BPF lets the kernel
  route the packet so the kernel can populate its FIB and neigh caches.
  Subsequent packets of the same flow can then be forwarded directly.
- **SNAT / MASQUERADE (`nat-outgoing`).** Full port-preserving SNAT
  requires port allocation state that BPF cannot safely produce; the
  `*tables` SNAT chain handles it. BPF signals this path by marking the
  packet (`CALI_SKB_MARK_NAT_OUT` / `CALI_SKB_MARK_MASQ`).
- **Pre-existing connections.** Connections established before BPF was
  loaded have no BPF conntrack entry. Rather than dropping them, BPF
  marks them `CALI_SKB_MARK_FALLTHROUGH` and lets `*tables` CT match
  against its own entry; see §12.
- **Third-party DNAT rules.** Some deployments rely on DNAT rules that
  another agent installed in the `*tables` raw/nat chain. BPF
  cooperates via the `SKIP_FIB` mark; see §13.
- **Host-originated service traffic.** Not strictly "deferring" — the
  `bpfnat` veth routes these packets back through BPF after `*tables`
  has had a chance to MASQUERADE them; see §7.

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


---

## 2. TC program layout

Attaching a TC program directly per interface does not scale: Felix
would have to reload the full program set every time policy changes
and every time it restarts. The current design decouples the programs
that rarely change (the packet-handling code) from the programs that
frequently change (per-endpoint policy).

### The preamble

The program that is actually attached to the TC hook on each
interface is a **preamble**
(`felix/bpf-gpl/tc_preamble.c` → `cali_tc_preamble`). It is tiny, fast
to load, and its only job is to:

1. Pick the IPv4 or IPv6 globals struct based on `skb->protocol` and
   copy it into per-CPU state. The rest of the program chain reads
   globals from that state, so a single copy amortises the cost.
2. If a log filter is configured for this interface, tail-call it.
3. Otherwise tail-call the "main" packet-processing program directly.

XDP has an equivalent preamble in `xdp_preamble.c`. The cgroup
connect-time hooks (§6) are attached directly — they have no preamble.

Because the preamble is cheap to reload, Felix can swap it per
interface without re-verifying the large program chain it fronts.

### Two-tier jump maps

Packet-processing programs are organised into two jump maps per
direction:

- **Generic programs map** — `cali_progs_ing` (TC ingress),
  `cali_progs_egr` (TC egress), `xdp_cali_progs` (XDP). Holds the
  code that is the same across all endpoints of the same kind: the
  main program, allowed/drop entry points, ICMP helpers, IP-frag
  helper, Maglev helper, TCP reset helper, etc. See
  `felix/bpf/hook/map.go` (`tcSubProgNames`, `xdpSubProgNames`).
- **Per-endpoint programs map** — `cali_jump_ing`, `cali_jump_egr`,
  `xdp_cali_jump`. Holds the policy program generated for each
  interface+direction, and the pcap log filter if one is installed
  (see §14). The policy program is regenerated and re-loaded
  whenever the rules for that endpoint change; the generic code above
  is untouched.

The split is what lets policy updates be cheap: Felix only has to
rewrite a couple of entries in the per-endpoint map, not replace any
attached programs. The kernel's tail-call mechanism makes the switch
atomic per-program-index.

Splitting the two TC directions (ingress vs egress) into separate maps
is a kernel-6.12 requirement (TCX programs on each direction have a
distinct program type and a jump map is typed for a single program
type). See the comment at the top of
`felix/bpf-gpl/jump.h`.

Both maps are sized generously — the per-endpoint map is sized for
many thousands of policy programs (240k slots) because each endpoint
gets two (one per direction) and the fast and debug variants each take
their own slot.

### Caching of generic programs

`hook.ProgramsMap` (in `felix/bpf/hook/map.go`) caches one loaded
object file per `AttachType`. An `AttachType` is the tuple of flags
that changes which sub-programs are compiled in: hook (TC
ingress/egress or XDP), whether the interface is a WEP, HEP, tunnel,
DSR-enabled, cgroup, etc. `LoadObj` loads the object at most once per
`AttachType` and returns a `Layout` that maps every sub-program to the
jump-map index it was placed at.

`GetApplicableSubProgs` filters the list based on capability: the
host-CT-conflict helper is only loaded for HEP egress, the Maglev
helper only where Maglev can be used, the IP-frag helper only on
attach points that run defrag. If the kernel rejects the IP-frag
program (older verifiers can fail on it), the load is retried with
that sub-program disabled — which is the only sub-program that may
legitimately be missing at runtime.

### skb->cb[0] and skb->cb[1]: allow/deny addresses

The policy program is per-endpoint but its callers are generic. The
convention is that before tail-calling into the policy program the
caller writes:

- `skb->cb[0]` = the jump-map index to tail-call into on **allow**,
- `skb->cb[1]` = the jump-map index to tail-call into on **deny**.

The policy program reads these and tail-calls into the appropriate
generic successor. This is what makes one compiled policy program
reusable from any caller. The convention is encoded in
`__CALI_JUMP_TO_POLICY` in `jump.h` — it always sets cb[0] to
`PROG_INDEX_ALLOWED` and cb[1] to `PROG_INDEX_DROP` on entry, but
callers that want a different continuation (for example the Maglev
program, which wants to re-enter the main program on allow) set their
own values before jumping.

### Fast path and debug path

Emitting a log line per packet is far too expensive for production,
so the dataplane is built twice: once without log statements ("fast
path") and once with them enabled ("debug path"). Each sub-program
therefore has two entries in `enum cali_jump_index` in `jump.h`, for
example `PROG_INDEX_MAIN` and `PROG_INDEX_MAIN_DEBUG`. The
`PROG_PATH(idx)` macro selects at compile time based on
`CALI_LOG_LEVEL`.

Both the fast-path and debug-path objects are loaded into the same
jump map, at different indices. `allocateLayout` in
`felix/bpf/hook/map.go` uses an offset of `SubProgTCMainDebug` when
placing debug programs, so fast-path and debug-path sub-programs never
collide.

Without a log filter, the preamble jumps to the fast-path main. With
a log filter, the filter decides per-packet whether to jump to the
fast-path or debug-path entry point. Log filtering is covered in §14.

### Attach-gap prevention

An interface exists briefly before Felix attaches a BPF program to it.
If another interface's BPF program forwarded a packet to the unready
one via `bpf_redirect`, the packet would bypass the `*tables` drop
rules that Felix maintains for this window. To prevent this, Felix
maintains the `cali_iface` hash map (key: ifindex,
`felix/bpf/ifstate/map.go` and `felix/bpf-gpl/ifstate.h`). The value
carries per-interface flags — notably `IFACE_STATE_V4_READY` /
`IFACE_STATE_V6_READY` and `IFACE_STATE_WEP` / `IFACE_STATE_HEP` —
plus the per-direction policy jump-map indices.

`fib_approve` (in `felix/bpf-gpl/fib_common.h`) consults this map
before approving a direct forward. For any connection that is not yet
confirmed in conntrack, a forward to a WEP whose interface is not
ready is refused; the packet is marked `CALI_SKB_MARK_SKIP_FIB` and
handed to the host stack, where the existing `*tables` attach-gap
drop rules apply. Confirmed (already-established) flows are allowed
through directly — the policy check happened when the flow was
created.

### Review notes for this section

- A new sub-program added to the generic program chain needs:
  - an entry in `enum cali_jump_index` in `felix/bpf-gpl/jump.h` with
    a matching `_DEBUG` variant,
  - a corresponding `SubProg*` constant and name in
    `felix/bpf/hook/map.go` (`tcSubProgNames` / `xdpSubProgNames`),
  - filtering in `GetApplicableSubProgs` if the program is not needed
    for every `AttachType`.
- A new per-endpoint program (something Felix reprograms per
  interface) belongs in the per-endpoint jump map (`cali_jump_*`),
  not the generic one. Generic programs are shared; per-endpoint
  programs are not.
- Any caller that tail-calls into the policy program must set
  `skb->cb[0]` and `skb->cb[1]` to valid jump-map indices first.
  Calling the policy program without setting them produces
  hard-to-debug drops on the allow or deny path.
- A change that adds a new field to the `cali_iface` value — or a new
  flag — needs a map-version bump (see `MapParams.Version` in
  `felix/bpf/ifstate/map.go`) because the kernel refuses to pin two
  different layouts under the same name.
- A change that makes BPF forward a packet directly that used to go
  through `*tables` should consult `fib_approve` (or an equivalent
  check) for the ifstate-ready flag; otherwise it reopens the
  attach-gap hole.


---

## 3. Intra-cluster traffic & service NAT

### The common case: pod to service

When a pod sends a packet to a service IP, the packet leaves the pod
and enters the host on the pod's host-side veth (`cali*`). The TC
program on that veth — a WEP egress program in kernel terms, WEP
_ingress_ policy in Calico terms — runs first.

The flow is:

1. **NAT lookup.** The program looks up `(dst_ip, dst_port, proto)` in
   the NAT frontend map (`felix/bpf/nat/`, consumed by
   `felix/bpf-gpl/nat_lookup.h` and friends). On a match, it picks a
   backend from the NAT backend map and rewrites the packet
   (DNAT).
2. **Policy.** The packet is tail-called into the per-endpoint policy
   program with the post-NAT destination, so policy is applied against
   the real backend rather than the service frontend.
3. **Conntrack create.** On allow, the program creates a pair of
   conntrack entries (§10): a forward entry keyed on the pre-NAT
   tuple, and a reverse entry keyed on the post-NAT tuple. The reverse
   entry is what lets return packets (backend → pod) be matched and
   un-NATed without another NAT lookup.

On subsequent packets, the forward entry is hit first and there is no
need to re-resolve the service. Return packets hit the reverse entry
and have the service frontend IP/port restored on the way back to the
pod.

### Same host

When the selected backend is on the same host, nothing special happens
on the wire — after DNAT, the packet has the backend pod's IP as its
destination, and the backend pod's host-side veth is a local interface
that the host can deliver to directly. `fib_approve` (§2) decides
whether to forward directly via `bpf_redirect` or hand the packet to
the host stack to route.

### Pod-service-self (no CTLB)

When the backend chosen for a service is the pod that originated the
traffic, this would naively resolve to a self-to-self packet. With the
CTLB (§6) this is not a problem because the CTLB rewrites the
destination at connect time and nothing ever leaves the pod. Without
CTLB, the host would have to loop the packet back, which fails:
`accept_local` is `0` by default on the pod's veth, and no socket
exists for the `(self, self)` 5-tuple anyway.

Calico handles this the same way kube-proxy does: it relies on
`*tables` MASQ to change the source, so the packet looks like it came
from the host and the pod accepts it.

The signal is carried on the conntrack entry:

- On WEP kernel egress, if the source IP equals the post-NAT
  destination IP, the program sets
  `CALI_CT_FLAG_SVC_SELF` on the new NAT-reverse entry (see
  `conntrack_types.h` and the NAT-create path in `tc.c`).
- On the way out after policy allow, if that flag is set on the flow,
  `CALI_SKB_MARK_MASQ` is set on the packet and FIB is disabled. The
  packet falls through to `*tables`, which MASQ-SNATs it.
- On the return leg (kernel ingress toward the pod, `CALI_F_TO_WEP`),
  the program detects the `CALI_SKB_MARK_MASQ` mark and restores the
  saved original source so the CT reverse-match works.

This is one of the reasons the CTLB is an important _optimisation_
(§6): when it is on, the self-loop is resolved in a single syscall
and none of the MASQ dance is needed.

### Review notes for this section

- Any change that alters how service NAT entries are keyed or that
  introduces new backend flags needs to bump the NAT map version
  (see `felix/bpf/nat/`) — kernel will refuse to pin two layouts
  under the same name.
- A change that makes BPF forward a packet that would previously have
  fallen through to `*tables` on the SVC_SELF path must preserve the
  `CALI_SKB_MARK_MASQ` + no-FIB behaviour, or re-implement the source
  restoration; otherwise pod-service-self breaks without CTLB.
- A new conntrack flag must be allocated in `conntrack_types.h`
  (`CALI_CT_FLAG_*`) and, if set on flow creation, must be considered
  on every path that reads the flow (forward and reverse).


---

## 4. External traffic (NodePort, DSR)

### NodePort: happy path

An external client opening a connection to a NodePort lands on the
node's main cluster interface (a HEP). The TC HEP-ingress program
runs:

1. Look up the `(local-host-IP, dst-port, proto)` tuple in the NAT
   frontend map. If the service exists, pick a backend.
2. If the chosen backend is a **local** pod, DNAT the packet and
   forward it to the pod's host-side veth as in §3.
3. If the chosen backend is on a **remote** node, wrap the packet in a
   VXLAN header (§8) with the destination being the node that hosts
   the backend, and hand it to the host stack to route out. The
   packet is marked "seen/approved" so Calico's egress HEP does not
   re-run policy on it.

### Return path (non-DSR)

On the backend node, the VXLAN decapsulation happens and NAT is
applied with local-only backend selection (so the same packet is not
re-ballooned to yet another node). Policy runs on the way into the
backend's veth.

On return, the backend's WEP program sees a packet whose destination
is the external client, and whose conntrack entry records that the
ingress came from a specific ingress node. The program wraps the
return packet back in VXLAN, destined for the node that originally
received the connection, and lets the host stack route it out. That
node decapsulates and routes the packet to the client.

The asymmetry is deliberate: the return path follows the forward path
because the ingress node is the only place that can un-DNAT the source
on return (it holds the conntrack reverse entry keyed on the original
client tuple).

### DSR

With DSR enabled, return traffic does _not_ go back through the
ingress node. The backend node simply SNATs the return packet (swapping
the backend IP for the ingress-node IP so the packet looks like it
came from the service) and lets the network deliver the packet
directly to the client.

DSR requires a supporting underlay: the client must be willing to
accept a reply from a node that is not the one it originally talked
to. The cluster admin opts in via `DSRSupport` configuration or, more
granularly, via `DSROptoutCIDRs` for destinations that cannot support
it. DSR is also a prerequisite for Maglev (§5).

### Intra-cluster access to NodePorts

It is legal for a pod to connect to a service via a node IP:port
rather than the service clusterIP. Rather than program a NAT entry
for every node IP × every service, Calico programs a special wildcard
frontend using `255.255.255.255` (IPv4) / all-ones (IPv6) in place of
the node IP (see `podNPIP` / `podNPIPV6` in
`felix/bpf/proxy/syncer.go`). When a pod's egress packet misses the
regular NAT lookup but the routing table says the destination is a
node, the WEP program retries the lookup against the wildcard entry
on the same port. On a hit, backend selection proceeds as for an
external NodePort request.

### Conflicting nodeport connections

When many clients hit a node port from the same source-IP (for
example: a cloud load balancer), the ephemeral ports seen by the
backend can collide across flows. Calico allocates source ports out of
a reserved range (`PSNATStart`/`PSNATEnd` on the attach point) and
retries with a random source port on collision. Changes to this
logic need to preserve port stability within a flow (return packets
must still match the CT entry).

### Review notes for this section

- A change to the NodePort lookup path must not break the wildcard
  (`255.255.255.255` / all-ones IPv6) fallback used for pods
  addressing a NodePort via a node IP. The wildcard entry lives in
  the same NAT frontend map as regular entries; changes to the key
  layout need to respect both.
- A new encapsulation path (e.g. a new overlay protocol) must
  preserve the "ingress node owns the CT reverse entry" invariant
  for the non-DSR case, otherwise return traffic cannot be un-NATed.
- A change to DSR gating must still compile-time-assert
  `CALI_F_DSR` only with `CALI_F_FROM_WEP` or `CALI_F_HEP`
  (see the `COMPILE_TIME_ASSERT` in `felix/bpf-gpl/bpf.h`). DSR
  makes no sense on WEP ingress.


---

## 5. Maglev load balancer

### What it is for

Ordinary services pick a backend per connection more-or-less at random
(first-available, round-robin, depending on the mode). That choice is
node-local: two LB nodes balancing the same service to the same set of
backends will pick different backends for the same external client
5-tuple.

Maglev-style services use a **consistent-hash** backend selection:
the choice is a deterministic function of the 5-tuple and the LUT. If
node A goes down mid-connection and the network redirects the client's
packets to node B, node B picks the _same_ backend that node A was
using and the connection can continue through B's conntrack. This is
what enables churn-tolerant load balancers in front of the cluster.

### Userspace: LUT generation

`felix/bpf/consistenthash/consistenthash.go` implements the standard
Maglev table-build: each backend generates a permutation over a prime
number of LUT slots, and the LUT is filled by sequentially picking the
next free slot from each backend's permutation. Felix publishes the
resulting table into a BPF map (key: `(svc_id, ordinal)`, value: NAT
destination; see `cali_maglev_lookup_elem` /
`cali_maglev_key` in `felix/bpf-gpl/maglev.h`).

### BPF: backend selection

Backend selection hashes the 5-tuple (plus protocol) with Jenkins
hashing (`jenkins_hash.h`), reduces modulo the LUT size, and reads the
NAT destination out of the Maglev map. The LUT size is a per-service
parameter carried in globals (`MAGLEV_LUT_SIZE`).

The selection code is small, but the hashing code _was not_ — the
original inlined form exceeded the kernel verifier's instruction
budget when placed inside the main program. Maglev therefore lives in
its own tail-called sub-program (`calico_tc_maglev` in `tc.c`,
registered as `SubProgMaglev` in `felix/bpf/hook/map.go`). The main
program detects that the target is a Maglev service and tail-calls
into the Maglev program before policy. Maglev fills in the post-NAT
destination and then tail-calls into policy as any other caller
would.

Only HEP-ingress programs on the main interface need Maglev; the
macro `HAS_MAGLEV` in `felix/bpf-gpl/bpf.h` expands to
`(CALI_F_FROM_HEP && CALI_F_MAIN)`, and `GetApplicableSubProgs` in
`hook/map.go` only loads the Maglev sub-program for attach types
where this is true.

### Mid-flow packets that don't match conntrack

Before Maglev, a mid-flow TCP packet with no conntrack hit was either
let through to `*tables` (might match a pre-existing kernel CT entry;
see §12) or dropped as unsolicited. Maglev adds a third class: a
mid-flow packet with no BPF CT hit whose destination is a Maglev
service. In this case the lb-node has just failed over onto this
node, so the packet genuinely is mid-flow but this node doesn't know
it yet. The handling is:

- Tail-call the Maglev program to pick the _same_ backend the previous
  node would have picked.
- Run it through policy — we cannot trust that the packet isn't
  spoofed — and create a conntrack entry with `CALI_CT_FLAG_MAGLEV`
  set (see `CALI_CT_FLAG_MAGLEV` in `conntrack_types.h`).
- On the backend node, the CT entry for this flow may already exist
  but have an older tunnel-source IP. Normally an IP mismatch on a
  hit would be treated as spoofing; the `CALI_CT_FLAG_MAGLEV` flag
  relaxes that check and updates the stored tunnel IP.

The `CALI_CT_MID_FLOW_MISS` → `CALI_CT_MAGLEV_MID_FLOW_MISS` transition
in `calico_tc_maglev` is what propagates the "this was a mid-flow
miss, go through the new-flow path" signal to the rest of the chain.

### Limitations

- **DSR required.** Without DSR, return packets must go back through
  the ingress lb node — but that node may have failed, and Maglev
  does not choose a different lb on the return path. Felix does not
  _block_ non-DSR Maglev to allow demos, but it is not a supported
  configuration.
- **NodePort.** Externally-advertised NodePort services per node cannot
  be Maglev because each node has its own NodePort IP — failing over
  to a different node means hashing into a different LUT keyed by a
  different IP.
- **CTLB.** The connect-time LB (§6) resolves the service at syscall
  time, before the TC program runs, so Maglev has no visibility. For
  pod-originated traffic this is not a regression (pods don't fail
  over), but it means Maglev is effectively external-traffic-only.
- **Traffic policy (internal/external).** `internalTrafficPolicy` and
  `externalTrafficPolicy=Local` restrict the pool of eligible
  backends. There is no consistent way to reconcile a deterministic
  hash with a node-dependent eligible pool, so these policies are
  ignored for Maglev services.

### Review notes for this section

- Any change to backend selection (adding fields to the hash,
  changing the hash, altering the LUT layout) must keep the selection
  deterministic across nodes. A single node producing a different
  backend for the same 5-tuple defeats the point.
- A new CT flag that interacts with tunnel-source changes or with
  mid-flow classification must explicitly decide its interaction with
  `CALI_CT_FLAG_MAGLEV`. In particular, do not re-enable spoofing
  checks for flows carrying that flag.
- Work that changes `HAS_MAGLEV` must keep the Maglev sub-program
  optional (not every attach type loads it). Similarly,
  `GetApplicableSubProgs` must not force-load it where it is not
  needed — the per-HEP program-array budget is finite.


---

## 6. Connect-Time Load Balancer (CTLB)

### What it does

The CTLB is a set of BPF programs attached to cgroup hooks rather
than to network interfaces. These hooks fire inside syscalls before
any packet is built:

- `cgroup/connect4`, `cgroup/connect6` — on `connect(2)`, the program
  does a NAT lookup on the destination the application passed and, if
  it matches a service frontend, rewrites the sockaddr in-place to
  point at the chosen backend. The connection is then established
  directly pod-to-pod; no TC program on the way out ever sees the
  service frontend IP.
- `cgroup/sendmsg4`, `cgroup/sendmsg6` — the equivalent for UDP
  `sendmsg(2)`.
- `cgroup/recvmsg4`, `cgroup/recvmsg6` — the reverse-NAT on read, so
  a UDP application sees the service IP/port in the received packet
  even though the packet on the wire carried a pod IP.

Source: `felix/bpf-gpl/connect_balancer.c` (IPv4),
`connect_balancer_v6.c` (IPv6 on an IPv6-only cgroup),
`connect_balancer_v46.c` (dual-stack), with shared helpers in
`connect.h` and `ctlb.h`. Userspace lifecycle is in
`felix/bpf/nat/connecttime.go`.

### Why it is an optimisation, not the default

CTLB eliminates per-packet NAT work: one lookup at connect time and
the kernel's socket is talking directly to the backend for the life
of the connection.

It also solves the service-access problem for **host-networked
processes**: a host-networked socket's traffic may leave the node on
a physical interface that the TC program for its packets cannot
predict (the default route could be wrong; the packet could be
dropped if there is no route). With CTLB the backend is already
resolved by the time the packet is built, so the routing question
answers itself.

The downsides are significant enough that Calico wants CTLB to be an
optimisation rather than a prerequisite. The bpfnat veth workaround
(§7) is what lets Felix run without CTLB.

### Limitations

- **Connected UDP.** `connect(2)` on a UDP socket records the chosen
  backend once. If the backend goes away, the socket keeps sending
  to the dead backend. TCP is not affected because each new
  connection runs the CTLB again.
- **Raw sockets bypass CTLB.** Any process using a raw socket builds
  the packet itself and the cgroup hook never fires. Such packets go
  through the regular TC path instead, which means they depend on
  the bpfnat veth to reach a TC program (§7).
- **Per-packet Maglev (§5) does not apply.** CTLB resolves the
  backend before Maglev's hashing logic has a chance to see the
  packet, so pod-originated traffic to a Maglev service gets a
  non-consistent-hash backend. Since Maglev is intended for external
  traffic anyway, this is acceptable.

The `ExcludeUDP` knob (`CTLB_EXCLUDE_UDP` in `ctlb.h`,
`LibBPF CTLBGlobalData.ExcludeUDP` on the userspace side) lets an
operator disable the UDP sendmsg/recvmsg hooks while keeping TCP
connect-time resolution, limiting exposure to the UDP stuck-backend
issue.

### Review notes for this section

- A change to the CTLB NAT path must keep the forward and reverse
  rewrites symmetric: if `sendmsg` rewrites a destination, the
  matching `recvmsg` must un-rewrite it for the same 5-tuple.
  Otherwise applications see the pod IP in response messages and
  reject them.
- A change that adds a new CTLB hook or removes the `ExcludeUDP`
  knob must preserve the ability to run without CTLB entirely — the
  bpfnat workaround depends on CTLB not being required for
  correctness, only for performance.


---

## 7. Host-networked workaround (bpfnat veth)

### Why it exists

CTLB (§6) resolves services at `connect(2)` time for applications that
make socket calls. It does not help:

- Applications that build packets themselves (raw sockets).
- Host-networked applications on kernels or configurations where CTLB
  cannot run.
- Any scenario the cluster admin has opted out of CTLB for.

Without CTLB, a host-originated packet to a service IP leaves the
host on whatever interface the routing table chooses, often with the
wrong source address, and no TC program on the chosen interface can
be expected to resolve the service. It might even be dropped for
having no route. The bpfnat workaround forces these packets through a
controlled point where a TC program _can_ run.

### Mechanics

Felix creates a veth pair whose two ends both live in the host
namespace:

- `bpfin.cali` (C-side identifier: `natin_idx` / `NATIN_IFACE`)
- `bpfout.cali` (C-side identifier: `natout_idx`)

See `felix/dataplane/linux/dataplanedefs/dataplane_defs.go` for the
Go-side constants, and `felix/bpf-gpl/globals.h` / `bpf.h` for the
C-side configurables. (The reference design document refers to these
as `bpfnatin`/`bpfnatout`; the implementation names are slightly
different.)

Felix programs host routes for every service ClusterIP via the
link-local gateway `169.254.1.1` (IPv4) / `2001:db8::1` (IPv6),
pointing at `bpfin.cali`. The effect is that any host-originated
packet destined for a service first exits through `bpfin.cali`.

- The packet immediately enters `bpfout.cali` (the peer end). The TC
  program there runs NAT, policy and conntrack creation as for any
  other HEP-ingress packet. Once resolved, it can forward directly
  to a local WEP, to a tunnel, or to the main interface.
- On the way back, the return packet arrives on the original
  interface, where the HEP-ingress program reverses NAT. The packet
  then has the host as its destination and is delivered normally.

### Mode selection

The feature has three modes (`hostNetworkedNATMode` in
`felix/dataplane/linux/bpf_ep_mgr.go`):

- **Disabled** — CTLB is on and handling both TCP and UDP; no bpfnat
  veth is created.
- **Enabled** — CTLB is off; every host-originated service access
  goes through the bpfnat veth. Selected via
  `BPFHostNetworkedNAT = Enabled`.
- **UDPOnly** — hybrid: CTLB handles TCP, bpfnat handles UDP. Selected
  indirectly by `BPFConnectTimeLB = TCP`, which leaves UDP to the
  slower but safer per-packet path so connected-UDP applications
  don't get stuck on a dead backend (§6). This mode is a compromise
  between the CTLB performance win and UDP correctness.

### The "tunnel trouble"

Tunnels require that packets leaving the host via the tunnel have the
tunnel interface's IP as their source, which in practice means
iptables/nftables SNAT runs somewhere on the egress path. The
complication is that when a host-originated packet to a service is
resolved to a _remote_ backend via a tunnel, the post-NAT destination
plus the tunnel-required SNAT gives the packet both a DNAT and an
SNAT — and BPF only knows about the DNAT.

Calico's approach, in BPF:

- The host-egress path (from the veth out) lets `*tables` MASQ set the
  source to the tunnel IP.
- The CT entry records that returning traffic must go back via
  `bpfnatout`-ish path so that reverse-NAT happens in BPF before the
  packet is delivered to a local socket.
- The `CALI_SKB_MARK_FROM_NAT_IFACE_OUT` mark (in
  `enum calico_skb_mark`) is what tells the next hop "this packet
  came through bpfnat; set your conntrack accordingly".
- The `CALI_SKB_MARK_MASQ` / `CALI_SKB_MARK_NAT_OUT` marks (§1) steer
  packets to `*tables` SNAT when needed.

A previously-considered alternative — doing SNAT in BPF, allocating
host source ports from BPF — was rejected because BPF cannot safely
coordinate port allocation with the kernel's socket tables. The
pragmatic compromise is port-only SNAT with random-port retry on
collision (same technique used for external-NodePort conflict; §4).

### RPF requirements

Routing host service access through the veth means that some packets
travel through the system via routes the kernel wouldn't normally
expect. The host-side sysctl requirements (enforced by
`setRPFilter("all", 0)` in `bpf_ep_mgr.go` when the feature is
enabled) are:

- `net.ipv4.conf.all.rp_filter = 0`. Any non-zero value on `all`
  trumps the per-interface setting.
- Per-interface: `rp_filter = 0` (off; BPF enforces RPF itself,
  see §9), `accept_local = 1` (the veth round-trip produces a
  host-source packet that the kernel would otherwise reject).

Changes that tighten kernel RPF sysctls on these interfaces break the
feature silently — packets are dropped by the kernel before BPF can
see them.

### NodePort turnaround

A host-networked process making a connection to its own node's
NodePort needs a little extra care. Depending on backend selection
the packet may need to be turned around (backend is a local pod) or
forwarded to another node. The turnaround is implemented by
detecting unseen packets on the loopback/main-interface egress path
whose target is the local host and whose NAT selects a local pod, and
redirecting them directly to the pod's veth (with `bpf_redirect_neigh`
on kernels that support it, or by bouncing off the bpfnat veth as a
fallback to populate the FIB/neigh caches). See `fib_co_re.h` for
the redirect path.

### Review notes for this section

- Any change to the service-IP routing should preserve the
  "service-IP → 169.254.1.1 via `bpfin.cali`" pattern for IPv4
  and the equivalent for IPv6. Removing those routes silently
  breaks host service access when CTLB is not handling the
  protocol.
- A change that introduces new sysctl dependencies (`rp_filter`,
  `accept_local`, or a new one) should be reflected in
  `bpf_ep_mgr.go`'s initialisation path; silent breakage from a
  sysctl set elsewhere is extremely hard to diagnose.
- When adding a new packet-path state that needs to survive the
  round-trip through the veth, prefer conntrack flags (which travel
  with the flow) over `skb` marks (which are cleared when a packet
  crosses the veth peer boundary — see the reference doc note about
  needing to clear marks manually on `bpfnatout`→`bpfnatin`).


---

## 8. VXLAN in eBPF mode

### Flow-based device

In the `*tables` dataplane, Calico creates a VXLAN device bound to a
specific VNI, source address and parent interface; the kernel then
performs encap/decap based on routing and the FDB.

For BPF, this is the wrong shape. We want the BPF program to decide
_per packet_ whether something goes into the tunnel, where it comes
out, and with what inner/outer addresses. The VXLAN device should
just apply the encap envelope the program has specified.

Felix therefore creates the VXLAN device in **flow-based** (aka
"external") mode when BPF is enabled: no fixed VNI, no fixed source,
no fixed destination. `netlink.Vxlan.FlowBased = true` in
`felix/dataplane/linux/vxlan_mgr.go`. The BPF program writes the
tunnel key (destination IP, VNI) via `bpf_skb_set_tunnel_key` before
redirecting to the device, and the device applies the envelope. On
ingress, the device decaps and the BPF program reads the original
key.

A flow-based device is incompatible with a fixed-VNI device. If Felix
detects a mismatched existing device on startup, it recreates it
(`vxlanLinksIncompat` in `vxlan_mgr.go`).

### Single device for dualstack

Kernel VXLAN in flow-based mode ties a device to an IP family
implicitly — two flow-based devices with the same port in the same
namespace produce ambiguity. Calico's compromise, when the cluster is
dualstack:

- Only one VXLAN device (`vxlan.calico`) is created; it handles both
  v4 and v6.
- The v6 VXLAN manager runs in `maintainIPOnly` mode: it programs the
  v6 local IP on the existing v4 device and programs v6 ARP/neigh
  entries, but does not create or manage its own device.
- The legacy `vxlan-v6.calico` device is torn down if it exists
  (`cleanUpVXLANDevice(VXLANIfaceNameV6)` in `int_dataplane.go`).

Constants: `VXLANIfaceNameV4 = "vxlan.calico"`,
`VXLANIfaceNameV6 = "vxlan-v6.calico"` in
`felix/dataplane/linux/dataplanedefs/dataplane_defs.go`.

### MTU and routing

Because one device serves both families, its MTU cannot be
family-specific. The device is set to the maximum MTU and per-family
MTU is enforced by the routes that point to it — for workload
traffic, by the workload veth MTU; for host-originated traffic, by
the MTU on the host route.

The VXLAN manager continues to program routes into the host routing
table — pod CIDR via `vxlan.calico`, remote host IP via the parent
interface. These routes are still needed because:

- BPF programs that do not know about the tunnel (for instance, a
  packet that took the host-stack fallback path) rely on the kernel
  to pick the tunnel device via routing.
- For workloads, the initial packet of a flow may traverse the host
  FIB before BPF establishes a direct redirect.

### FDB

The FDB (`vxlanfdb/`) is not used to route tunnel packets in BPF
mode — the BPF program sets the tunnel key directly — but it is still
populated with neigh entries so the kernel can resolve a peer MAC
when a packet does take the host-stack path.

The v6 manager explicitly sets `vxlanfdb.WithNeighUpdatesOnly()` in
BPF dualstack mode because the device is shared and full FDB updates
would conflict with the v4 manager.

### Migration from `*tables` to BPF

Switching an existing `*tables` cluster to BPF recreates the VXLAN
device (flow-based is incompatible with the pre-existing fixed-VNI
shape). Deleting and recreating the device drops the kernel's
conntrack for flows that were established through the old device —
one of the unavoidable costs of the dataplane switch. This is
separate from the broader "preserve pre-existing TCP flows" story
in §12, which handles flows whose conntrack was in `*tables` rather
than pinned to a specific device.

### Review notes for this section

- Any change to the VXLAN device attributes in `vxlan_mgr.go` needs
  a matching entry in `vxlanLinksIncompat` so that a mismatched
  existing device is detected and recreated; otherwise the BPF
  programs and the device disagree on how tunnel keys are set.
- Dualstack work on the VXLAN device must respect the "only one
  device" invariant — setting up a second `vxlan-v6.calico` device
  in BPF mode breaks tunnel-key resolution.
- BPF programs that program new tunnel behaviour must use
  `bpf_skb_set_tunnel_key` (or equivalent) on a flow-based device;
  the device will not apply anything that does not come in via the
  tunnel key.


---

## 9. Reverse-path filter (RPF)

### Why RPF is in BPF

A large part of Calico's packet handling involves forwarding packets
directly with `bpf_redirect`, which bypasses the kernel's RPF check.
The kernel's per-interface `rp_filter` sysctl is also relaxed or
disabled on several Calico-managed interfaces — bpfnat, tunnel
devices — because the kernel would otherwise reject packets that
Calico has intentionally routed via unusual paths (§7).

The result is that the kernel cannot be trusted to enforce RPF for
Calico traffic. BPF therefore does it directly. See
`felix/bpf-gpl/rpf.h`.

### WEP RPF

For packets arriving on a workload veth, the check is simple and
always strict: look up the source IP in the BPF route table; the
route must point at the same workload interface the packet arrived
on, and the target must be a local workload. `wep_rpf_check` in
`rpf.h`.

Spoofing can be allowed per-(ifindex, source-IP) via the AllowSources
map when `WORKLOAD_SRC_SPOOFING_CONFIGURED` is set. When the check
passes via that bypass, the flag `CALI_ST_SUPPRESS_CT_STATE` is set
so that the conntrack entry isn't created with a bogus source — an
explicit decision to accept the packet but not to build a flow
record around it.

### HEP RPF

Host-endpoint RPF has to cope with the general routing table and so
cannot simply compare ifindices. `hep_rpf_check` uses the BPF FIB
helper with the source and destination swapped: if the FIB succeeds,
the packet has a valid reverse route; if the ifindex on that reverse
route equals the arrival ifindex, the check is strict-ok; otherwise
it is loose-ok (accepted in loose mode, rejected in strict mode).

RPF mode is a per-interface setting set by the `RPFEnforceOption`
field on the attach point and carried to BPF via the
`CALI_GLOBALS_RPF_OPTION_ENABLED` and `CALI_GLOBALS_RPF_OPTION_STRICT`
flags.

Special cases:

- ICMPv6: bypasses RPF (link-local traffic is essential for IPv6
  operation and wouldn't survive strict checks).
- Link-local source with host-local destination is accepted
  (DHCP-style address resolution).

### Why the kernel's rp_filter is relaxed

Running with loose BPF RPF on top of strict kernel RPF is not safe —
when `rp_filter` is non-zero on an interface that matters, the
kernel applies its own RPF _before_ BPF's, and can drop a packet that
BPF intended to accept on one of the indirect routing paths. The
bpfnat veth (§7), the tunnel devices, and similar "packet arrives on
interface X but we expect the source to be routable via Y" paths all
depend on the kernel not second-guessing BPF.

Felix explicitly sets `net.ipv4.conf.all.rp_filter = 0` when the
bpfnat feature is enabled; per-interface sysctls are set to loose
(`2`) on interfaces where Calico forwards packets that may appear
misrouted to the kernel. BPF does the real check.

### Review notes for this section

- A change that makes a new interface type Calico-managed must decide
  whether BPF RPF needs to run on it, and set `RPFEnforceOption`
  accordingly. The default (RPF on) is right for most HEPs; tunnel
  interfaces and bpfnat need bespoke handling.
- Any change that needs the kernel to _not_ second-guess a BPF
  routing decision must relax the relevant `rp_filter` sysctl.
  Setting `all.rp_filter = 1` anywhere else in the codebase breaks
  bpfnat and tunnel paths.
- A change that bypasses RPF — for example, a new allow-source
  mechanism — should go through the same `CALI_ST_SUPPRESS_CT_STATE`
  path so that the conntrack table does not fill up with entries
  keyed on spoofed addresses.


---

## 10. Conntrack & cleanup

### Entry shapes

The BPF conntrack table (`cali_v4_ct`, `cali_v6_ct`) holds three kinds
of entry (`TypeNormal`, `TypeNATForward`, `TypeNATReverse` in
`felix/bpf/conntrack/map.go`):

- **Normal.** Non-NAT'd flows. One entry per flow, keyed by the
  5-tuple. Covers both directions.
- **NAT forward.** The pre-NAT view of a NAT'd flow. Keyed on the
  pre-NAT 5-tuple; value contains the reverse key to look up the NAT
  backend state.
- **NAT reverse.** The post-NAT view. Keyed on the post-NAT 5-tuple;
  carries the NAT service details (backend, source-port rewrite,
  flags like `CALI_CT_FLAG_SVC_SELF`, `CALI_CT_FLAG_MAGLEV`).

Creating a NAT'd flow means creating both. Destroying a NAT'd flow
means destroying both — atomically enough that BPF never sees only
one side. The cleanup pipeline is built around this requirement.

### Cleanup: three layers

#### 1. Userspace scanners

A periodic sweep in Felix iterates the conntrack map and runs each
entry through a chain of `EntryScanner` instances
(`felix/bpf/conntrack/scanner.go`, scanners in
`felix/bpf/conntrack/cleanup.go`):

- **`LivenessScanner`** — reads the entry's timestamp and per-protocol
  timeout (`timeouts.Timeouts`), marks expired entries for deletion.
  For NAT'd flows, bookkeeping lives on the reverse entry — the
  forward-entry scanner follows the reverse-key pointer and decides
  based on the reverse entry's timestamp. A forward entry with no
  reverse counterpart is deleted immediately (it is useless without
  the reverse).
- **`StaleNATScanner`** — for each NAT'd flow, checks whether the
  service frontend still has the chosen backend. UDP stale-NAT
  entries are deleted from userspace immediately, because
  subsequent packets on the same flow would otherwise be forwarded
  to a dead backend.
- **`WorkloadRemoveScannerTCP`** — receives workload-IP-removed
  events from the BPF endpoint manager and, on the next sweep, marks
  TCP flows involving those IPs for **TCP reset** rather than silent
  deletion. The next packet on the flow triggers Felix to emit an
  RST, so clients see the connection drop immediately rather than
  hanging until the TCP timeout.

The scanners return a `ScanVerdict` per entry:
`ScanVerdictOK`, `ScanVerdictDelete`, `ScanVerdictSendRST`.

#### 2. BPF cleaner

Deleting entries directly from userspace is slow and creates a window
where the forward entry is gone but the reverse is not (or vice
versa). Felix therefore uses a BPF cleaner program
(`felix/bpf-gpl/conntrack_cleanup.c`, `BPFProgCleaner` in
`felix/bpf/conntrack/bpf_scanner.go`) for the common expired-entry
case:

- When the userspace liveness scanner marks an entry for deletion,
  Felix inserts a record into the **conntrack cleanup map**
  (`cali_ct_cleanup`, version `cleanupv1`). For a non-NAT entry the
  record's forward and reverse keys are the same; for a NAT entry
  the record captures _both_ keys and _both_ timestamps.
- Every N entries (currently 1000), Felix runs the BPF cleaner
  program. The program iterates the cleanup map, re-reads the
  corresponding conntrack entries, and deletes them only if the
  timestamps still match the recorded timestamps. This races safely
  with traffic that might have refreshed the flow: if the entry has
  been touched since being marked, the timestamp differs and the
  cleaner leaves it alone.
- NAT forward and reverse are deleted in the same program
  invocation, so the "only one side present" window is bounded by
  the cleaner program's execution (microseconds), not the userspace
  iteration.

#### 3. LRU fallback

The conntrack maps use an LRU hash backing, so if both the userspace
scanners and the BPF cleaner fall behind and the map fills, the
kernel evicts the oldest entries. This is a last-resort safety net,
not a primary cleanup path — losing an active flow's CT entry
produces a very visible application-level failure, so normal
operation should never rely on it.

### Timestamps

Conntrack entries carry kernel-time (`CLOCK_MONOTONIC`) timestamps
set by the BPF programs. Userspace caches the kernel-time translation
to avoid a per-entry `clock_gettime` overhead
(`LivenessScanner.goTimeOfLastKTimeLookup`). Any change to how
timestamps are stored needs to match on both sides — the BPF write
and the Go-side reader must agree on units and reference clock.

### Review notes for this section

- A new conntrack entry field needs a map-version bump
  (`cali_v4_ct`/`cali_v6_ct` have `Version: 4` at the time of
  writing). The kernel refuses to pin two layouts under the same
  name, and older Felixes reading a newer map will misparse.
- A new scanner should return the smallest verdict that does the job
  (`ScanVerdictOK` for no-op) and should be idempotent across
  iterations. Scanners may be called once or many times per sweep
  depending on how much Felix batches.
- A change to NAT-forward/reverse bookkeeping must preserve the
  invariant that both sides are deleted together. Either use the
  BPF cleaner path (insert into `cali_ct_cleanup`) or accept the
  race (and document why it is safe) — never delete a single side
  from userspace.
- Do not rely on LRU eviction to keep the table healthy. A PR that
  produces more conntrack entries per second than the cleanup
  pipeline removes will silently lose active flows once the map
  fills.


---

## 11. IP fragmentation

### Why it's hard

Fragments are hostile to stateless BPF programs. Only the first
fragment carries L4 headers, so only the first fragment can be keyed
against conntrack. Fragments may arrive out of order, so even the
first fragment may arrive second. BPF cannot pause a packet waiting
for more; it must allow, drop or modify immediately.

### HEP-only defrag

Calico defragments only on HEP ingress, where the cluster has no
control over the network that produced the fragments. Workload
traffic is assumed not to be reordered (the workload and the host
share a kernel, and modern kernels do not reorder small local
packets).

The implementation is a tail-called sub-program,
`calico_tc_skb_ipv4_frag` in `felix/bpf-gpl/tc_ip_frag.c`,
registered as `SubProgIPFrag` in `felix/bpf/hook/map.go`. It is
IPv4-only.

The algorithm:

- If the first fragment arrives first, the defrag program creates a
  **fragment-forwarding** conntrack entry (`cali_v4_frgfwd`,
  `FwdMap` in `felix/bpf/ipfrags/map.go`) that records the L4
  ports and the disposition reached by policy. Subsequent fragments
  match on `(src_ip, dst_ip, ip_id)` and are allowed through without
  policy re-evaluation.
- If fragments arrive out of order, the program stores each fragment
  in the **fragment-reassembly** map (`cali_v4_frags`). Once all
  fragments are in, the program reassembles the packet in place and
  re-runs policy on the full payload.
- The per-CPU temporary map (`cali_v4_frgtmp`) is reassembly
  scratch space — each CPU gets a 1.5k-byte buffer so the program
  doesn't blow the BPF stack.
- The reassembled packet is forced through the host stack
  (`CALI_ST_SKIP_REDIR_ONCE`) rather than `bpf_redirect`'d. Why: the
  reassembled packet is almost certainly larger than the next-hop's
  MTU, and the host stack is the only component that can
  re-fragment it for the next hop.

### Pragmatic compromises

The reference design document lays out several properties that are
_not_ strictly satisfied and this is deliberate:

- A middlebox should not defragment — but without defrag we cannot
  police a fragmented packet safely. Calico accepts the
  middlebox-defragmentation cost at HEP ingress because the
  alternative is either "drop all fragments" (breaks real traffic)
  or "accept all fragments" (security hole: fragments bypass policy).
- eBPF cannot build packets bigger than 16 kB. Extremely large
  packets that need reassembly across many fragments will fail —
  this is a best-effort feature.
- In the unlikely case of reordering, some or all fragments may be
  lost. The in-order fast path avoids this by creating the
  forwarding entry on the first fragment; out-of-order fragments
  fall back to the reassembly map.

### Timeouts

The `IPFRAG_TIMEOUT` global controls how long a fragment-tracking
entry may live. Absent a configured value, the kernel's default
fragment timeout applies. A timer-based cleanup removes entries that
were never completed (e.g. a last fragment that never arrived).

### Review notes for this section

- A new invariant that says "all fragments of a flow must be
  policy-approved together" should be checked against the
  fragment-forwarding map — fragments of an _approved_ flow are
  allowed through without re-running policy.
- A change to the BPF defrag path must handle the load-time opt-out
  (`calico_tc_skb_ipv4_frag` has `SetProgramAutoload(false)` when
  the attach type cannot defrag, and loading retries with it
  disabled on verifier failure; see `LoadObj` in
  `felix/bpf/hook/map.go`). A new sub-program the defrag path
  depends on must tolerate `SubProgIPFrag` being absent.
- IPv6 fragmentation is not currently handled; any change that needs
  IPv6 fragments to be seen by policy must add an equivalent for v6
  rather than assuming the v4 path handles both.


---

## 12. Switching from `*tables` to eBPF

### What breaks on the switch

When a running cluster switches Felix's dataplane from `*tables` to
BPF, three kinds of flow are at risk:

- **Flows established before BPF was ever loaded.** The BPF conntrack
  table is empty, so a mid-flow packet will miss.
- **Flows established before Calico was installed.** Same as above —
  Calico typically honours pre-existing connections in `*tables`
  mode, and users expect the switch not to break that.
- **Flows whose kernel conntrack was pinned to a device that BPF
  recreates.** The VXLAN device recreation (§8) is the clearest
  example: the tear-down drops kernel CT state for flows through
  that device, and they cannot be recovered.

Calico handles the first two with the "mid-flow fallthrough" pattern.
The third is unavoidable and is accepted as a cost of the switch.

### Mid-flow TCP fallthrough

TCP is stateful: a non-SYN packet with no BPF conntrack hit is
unambiguously a mid-flow packet. BPF and `*tables` cooperate to let
it through:

- On host ingress, a BPF program that sees a mid-flow TCP miss sets
  `CALI_SKB_MARK_FALLTHROUGH` on the packet (`bpf.h` enum
  `calico_skb_mark`) and returns `TC_ACT_UNSPEC`, letting the packet
  continue into netfilter.
- Felix installs a rule
  (`InternalDataplane.bpfMarkPreestablishedFlowsRules` in
  `int_dataplane.go`) that matches packets on their Linux conntrack
  state (ESTABLISHED/RELATED) and sets
  `CALI_SKB_MARK_CT_ESTABLISHED`
  (`MarkLinuxConntrackEstablished` = `0x08000000` in
  `felix/bpf/tc/defs/defs.go`).
- On the next TC hook the packet hits (for example, the kernel-egress
  program on the destination workload's veth), BPF sees the
  `CT_ESTABLISHED` mark and lets the packet through without
  re-running policy — the fact that Linux conntrack matched is
  evidence that the flow was previously vetted.

This gives correct behaviour for pre-existing flows as long as Linux
conntrack still has their state. It also preserves connections that
pre-date the Calico install entirely: same mechanism.

### UDP has no mid-flow

UDP does not signal flow establishment in the protocol, so BPF
cannot distinguish "a packet from a long-running UDP flow" from "a
fresh datagram". Any UDP packet that misses BPF CT is treated as new.
If the previous `*tables` dataplane had NAT'd the flow to a specific
backend, the BPF dataplane may now pick a different backend on first
sight. For protocols that care about backend affinity this manifests
as a brief disruption. The reference design document accepts this as
a valid tradeoff given UDP's delivery semantics; there is no
fallthrough shim for UDP.

### Operator coordination

Operator-based installs minimise the mixed-mode window by:

- Rolling out the BPF-capable Felix image via the normal rolling
  update.
- Once all nodes are running the new image, flipping the Felix
  configuration to enable BPF so every Felix switches more or less
  simultaneously.

During the mixed window, BPF nodes and `*tables` nodes coexist and
inter-node traffic uses the `*tables` dataplane path (since the BPF
node's encap/decap expects its peer to understand the BPF wire
format, which `*tables` doesn't).

### Review notes for this section

- A change to the mid-flow fallthrough path must preserve two
  invariants: (a) every mid-flow TCP miss on host ingress gets the
  `FALLTHROUGH` mark, and (b) every subsequent BPF program that
  sees a packet with `CT_ESTABLISHED` treats it as approved. Break
  either and the switch starts dropping existing TCP connections.
- A new rule generator for either iptables or nftables that emits
  the "mark pre-established flows" rule must keep the mark value
  (`0x08000000`) in sync with `MarkLinuxConntrackEstablished` in
  `felix/bpf/tc/defs/defs.go`. The mask must include that bit
  _and_ not overlap with any other BPF-owned mark.
- A change that adds BPF connection-establishment handling for
  UDP must not weaken the BPF-side handling of a UDP packet as
  independently processable — UDP applications tolerate packet loss
  but not out-of-order NAT rewrites on an existing flow.


---

## 13. 3rd-party DNAT on host traffic

### What users want

Sometimes another agent on the host installs iptables/nftables DNAT
rules to redirect traffic addressed to a host port to a workload
port. A typical shape:

- Client sends `C:* -> H:hp` (H = host, hp = host port).
- Host DNAT rewrites destination: `C:* -> W:wp` (W = local workload,
  wp = workload port).

Without BPF this is straightforward: the packet hits the nat
PREROUTING chain, gets DNAT'd, and is routed to the workload. Return
traffic hits the nat POSTROUTING SNAT and the client sees the reply
from `H:hp`.

### Why it doesn't "just work" with BPF

Two problems:

1. **BPF FIB lookup bypasses netfilter.** When BPF's FIB-based
   forwarding succeeds, the packet is redirected directly to the
   workload veth and netfilter never runs — including the 3rd-party
   DNAT rule.
2. **Calico NOTRACK rules.** Calico's `*tables` raw-PREROUTING rules
   set NOTRACK on workload traffic (this is how BPF takes over from
   kernel conntrack). Kernel NAT requires tracked connections, so
   a DNAT rule that would otherwise match gets skipped.

### The fix: SkipFIB

Calico's raw-PREROUTING setup in
`felix/rules/static.go` (search for `MarkSeenSkipFIB`) installs a
rule that sets the **SkipFIB** skb mark on any packet whose
destination is the local host:

```
match: destination addrtype=LOCAL
action: set mark 0x01100000/0x01100000  (CALI_SKB_MARK_SKIP_FIB)
comment: "Mark traffic towards the host - it is TRACKed"
```

The mark is `tcdefs.MarkSeenSkipFIB`, which equals
`CALI_SKB_MARK_SKIP_FIB` on the BPF side
(see `felix/bpf-gpl/bpf.h` `enum calico_skb_mark`). Because this
happens in raw-PREROUTING, it runs _before_ any DNAT chain, so the
destination is still the host IP at match time.

What this buys:

- The packet is left TRACKed (Calico's NOTRACK rule doesn't apply to
  local-dest traffic), so any 3rd-party DNAT rule in nat-PREROUTING
  can match and rewrite the destination normally.
- Once the packet reaches BPF at the workload veth's ingress, the
  BPF program sees the `SKIP_FIB` mark and, on conntrack entry
  creation, copies it into the CT entry as
  `CALI_CT_FLAG_SKIP_FIB` (defined in
  `felix/bpf-gpl/conntrack_types.h`, mirrored in
  `felix/bpf/conntrack/v4/map.go` as `FlagSkipFIB`).
- Reply packets hit the CT entry, see the flag, and are routed via
  the host stack rather than `bpf_redirect`'d — so the host nat
  POSTROUTING chain (including Calico's own MASQ and the 3rd-party
  SNAT counterpart) runs normally.

### Review notes for this section

- The raw-PREROUTING rule is the _only_ place the SkipFIB mark is
  set by `*tables`. Changes to the rule-generator layer must keep
  this rule and must keep its `addrtype=LOCAL` match — a broader
  match unnecessarily forces the host stack for traffic that BPF
  could forward, a narrower match breaks 3rd-party DNAT.
- `CALI_CT_FLAG_SKIP_FIB` must be preserved on conntrack writes that
  refresh or update an entry. Losing the flag on a subsequent packet
  would re-enable FIB for the return leg and break the 3rd-party
  DNAT's return path.
- A change that introduces a new BPF mark in the `0x01100000`
  region must confirm it doesn't overlap with `SKIP_FIB` or the
  other bits the raw-PREROUTING rule sets — the whole mark word
  is routed back into BPF.


---

## 14. Debug log filters

### The problem

With `BPFLogLevel = debug`, BPF programs emit a log line at every
interesting point in the packet path. That is indispensable when
diagnosing a rare issue and catastrophic when run blindly on a loaded
cluster — the log stream overwhelms the ring buffer, packets hit
slower code, and the signal is drowned by noise.

BPFLogFilters let an operator target debug logging to a small,
specific subset of packets ("only TCP to port 80 on these two
pods") so the cost is paid only for traffic that matters.

### Fast path and debug path

The dataplane is compiled twice:

- The **fast path** has all logging calls optimised out
  (`CALI_LOG_LEVEL < DEBUG`). This is what runs on every packet in
  production.
- The **debug path** is the same code with logging enabled
  (`CALI_LOG_LEVEL == DEBUG`). Each sub-program (main, policy,
  allowed, drop, etc.) has a `_DEBUG` variant in
  `enum cali_jump_index` (§2).

When no filter is configured, only the fast path is loaded. When a
filter is configured, both paths are loaded: same map, different
indices, thanks to the `SubProgTCMainDebug` offset in
`allocateLayout` (`felix/bpf/hook/map.go`).

### pcap → eBPF

The filter itself is a BPF program compiled from a pcap expression.
Doing the compilation at runtime is much cheaper than hand-assembling
a filter per rule, and reuses the familiar pcap language.
Implementation in `felix/bpf/filter/filter.go`:

1. `pcap.CompileBPFFilter` (gopacket/pcap) turns the expression into
   classic-BPF (cBPF) instructions.
2. `cBPF2eBPF` converts those to eBPF bytecode in our
   `felix/bpf/asm/asm.go` representation.
3. The filter's prologue copies packet bytes into a per-CPU scratch
   buffer (the state map) so the cBPF offsets resolve correctly; the
   epilogue either tail-calls the debug-path main (on match) or
   falls through to the fast-path main (on miss).

The filter uses the same `skb->cb[0]` / `skb->cb[1]` convention as
every other tail-caller (§2):

- `skb->cb[0]` = fast-path main index (no match → go here),
- `skb->cb[1]` = debug-path main index (match → go here).

### Integration with the preamble

`tc_preamble.c` checks `globals->data.log_filter_jmp`. If it is not
`-1`, the preamble sets up `skb->cb[0]` and `skb->cb[1]` and
tail-calls into the filter; otherwise it jumps directly to the
fast-path main. The per-endpoint jump map (`cali_jump_prog_map`)
holds the filter, not the generic program map — filters are
per-interface.

### BPFLogFilters and bpfCTLBLogFilter

- `BPFLogFilters` is a comma-separated list of `key=value` entries.
  The key is an interface name, `all`, `hep` or `wep`; the value is
  the pcap expression. This lets an operator attach different
  filters to different interfaces or to whole classes of
  interfaces.
- `bpfCTLBLogFilter` is separate because CTLB programs run inside
  syscalls and have no packet to match against a pcap expression.
  The CTLB filter is effectively a boolean "do/don't log"
  per-CTLB-hook; the docstring in `config-params.json` notes that
  it must be `all` to see CTLB logs when `BPFLogFilters` is set,
  so that one knob doesn't accidentally silence the other.

### Review notes for this section

- A change that adds a new BPF sub-program to the path must add a
  matching `_DEBUG` variant in `enum cali_jump_index` and keep the
  fast/debug offset in `allocateLayout` consistent. Otherwise the
  debug path cannot reach the new program.
- Any change to `skb->cb[0]`/`skb->cb[1]` semantics must be
  reflected in the filter compiler's epilogue
  (`programFooter` in `filter.go`) — the filter and the main
  programs have to agree on which slot is "allow" and which is
  "deny/fast".
- A PR that introduces a new type of filter target (for example,
  filtering by metric rather than pcap expression) should reuse the
  dual-path loading scheme rather than inventing a new one. The
  machinery to load two path-variants of every sub-program is
  already there; duplicating it across filter types is how this
  area becomes unmaintainable.


---

## 15. QoS

### Scope of BPF involvement

Calico's QoS controls cover bandwidth, packet rate, connection count
and DSCP. Not all of those live in BPF:

- **Bandwidth** is handled by tc qdiscs on the workload veth and by
  the upstream CNI bandwidth plugin. BPF is not involved.
- **Connection count** (`IngressMaxConnections` / `EgressMaxConnections`
  on a workload endpoint) is enforced via `*tables` rules — look for
  `LimitNumConnections` in `felix/rules/endpoints.go`. BPF is not
  involved.
- **Packet rate** is enforced by BPF (per-workload token bucket).
- **DSCP** marking is applied by BPF on egress to external
  destinations and HEPs.

The BPF-specific implementation lives under `felix/bpf/qos/` (Go) and
`felix/bpf-gpl/qos.h` (C).

### Packet rate

Packet rate is enforced per-interface, per-direction. The BPF map
`cali_qos` (`felix/bpf/qos/map.go`, key `(ifindex, ingress)`)
holds the TBF state per attach point. The value struct carries the
configured `packet_rate` (tokens/second) and `packet_burst` (bucket
size), plus mutable token count and the last-update timestamp,
protected by a BPF spinlock.

`qos_enforce_packet_rate` in `qos.h`:

- No entry in the map → no rate limit → accept.
- Under the spinlock: advance the token count based on elapsed time,
  cap at burst, decrement by one per accepted packet.
- No tokens → drop with `TC_ACT_SHOT`.

The per-direction `INGRESS_PACKET_RATE_CONFIGURED` /
`EGRESS_PACKET_RATE_CONFIGURED` flags (set on the AttachPoint and
propagated to BPF globals) let the program skip the map lookup
entirely when the feature isn't configured for that attach point.

### DSCP

DSCP marking is configurable via the `qos.projectcalico.org/dscp`
annotation on a HEP or WEP. The value is carried in BPF globals as
`EGRESS_DSCP` and applied on egress:

- On a new egress connection, if DSCP is configured and the
  destination is outside the cluster or on a HEP (see
  `cali_rt_flags_should_set_dscp` in `felix/bpf-gpl/routes.h`), the
  BPF program sets `CALI_CT_FLAG_SET_DSCP` on the conntrack reverse
  entry (`conntrack_types.h`).
- On every subsequent egress packet on that flow, `CALI_ST_SET_DSCP`
  is raised from the CT flag and `qos_dscp_set` rewrites the IP
  header:
  - IPv4: upper six bits of the TOS byte (checksum is recomputed).
  - IPv6: upper four bits of `priority` and the top two bits of
    `flow_lbl[0]` (traffic class = DSCP + ECN).

The ECN bits are preserved in both address families. Istio's DSCP
hook (for L7 tagging) uses a second global, `ISTIO_DSCP`.

### Review notes for this section

- A new BPF-enforced QoS field needs a slot in the `cali_qos` value
  struct. That struct contains a `bpf_spin_lock` at offset 0, which
  must stay at offset 0; its presence also means the map is a
  `BPF_MAP_TYPE_HASH` (not LRU/percpu/etc.). Do not relax those
  without a plan for concurrent access.
- Any change to packet-rate accounting must preserve the spinlock
  discipline: all reads and writes of `packet_rate_tokens` /
  `packet_rate_last_update` happen under the lock, and the drop
  decision is part of the atomic section. Dropping outside the lock
  allows overshoot.
- A change that extends DSCP marking to new paths (a new tunnel
  type, a new forwarded-packet case) must set `CALI_ST_SET_DSCP`
  based on the CT flag, _not_ on the globals alone — globals are a
  per-attach-point configuration, not a per-flow decision. The CT
  flag is what records the per-flow policy decision.
- If a feature is added that looks like it belongs in the QoS chain
  but only needs per-packet iptables-visible behaviour (e.g. a
  simple drop rule), prefer placing it in the `*tables` rule
  generators — `felix/rules/endpoints.go` already handles the
  connection-count and similar per-WEP knobs.


---

## 16. Cross-cutting review notes

The per-section review notes cover what a reviewer should check inside
a given topic. This final section collects the handful of checks that
don't belong to any single topic — they come up repeatedly in BPF
dataplane review because several subsystems happen to share them.

### Changes that touch shared maps

- A change to the key or value layout of a pinned BPF map needs a
  version bump on that map's `MapParameters.Version` in
  `felix/bpf/.../map.go`. Two Felixes running different versions
  cannot share the same pinned map, and the kernel refuses to pin
  two layouts under one name. Bumping the version triggers the
  rename-and-migrate path in `felix/bpf/maps/` and lets old Felix
  versions ignore the new pin.
- A new map that BPF programs update from multiple CPUs
  concurrently needs a clear consistency story: spinlock (like
  `cali_qos`), per-CPU (like `cali_v4_frgtmp`), or LRU with
  idempotent semantics (like the conntrack maps). Ad-hoc
  hash-with-no-locking is almost never the right choice for
  programs that write.

### Changes that introduce new BPF sub-programs

See §2 for the full list. The short version: a new sub-program needs
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
- Is the target interface ready (§2)? If not, defer via
  `SKIP_FIB`.
- Is there a third-party DNAT in `*tables` the packet might need?
  If its destination is the local host, defer (`SKIP_FIB`).

A PR that "improves performance by forwarding earlier" should list
which of these it has considered.

### Changes that affect what runs under `*tables`

The `*tables` side in BPF mode is thinner than in the pure-`*tables`
dataplane — most policy is in BPF. Rules that remain are primarily:

- The pre-established flow marking rule (§12).
- The SkipFIB-for-local-dest rule (§13).
- MASQ/SNAT chains for outgoing traffic.
- The attach-gap drop rules (§2).
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
  `cali_progs_ing` vs `cali_progs_egr` is the workaround (§2).
- `bpf_redirect_neigh` availability — §7's bpfnat turnaround falls
  back to bounce-off-the-veth when this helper isn't available.
- IP defrag sub-program (`SubProgIPFrag`) — older verifiers reject
  it; the loader retries without it (§11).

A PR that uses a new kernel-version-dependent helper must have a
fallback path, or the dataplane will fail to load on older kernels
Calico still supports.

