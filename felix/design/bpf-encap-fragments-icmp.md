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

# eBPF dataplane — Encapsulation, fragments, ICMP errors

How BPF shapes packets that don't go straight onto the wire: the flow-mode VXLAN device that lets BPF set per-packet tunnel keys (covering both NodePort-forwarding VXLAN and the pod-to-pod overlay; reserved VNI `0xca11c0`), IPv4 fragment defrag/tracking on HEPs, and BPF-synthesised ICMP errors (TTL-exceeded, frag-needed/MTU, port-unreachable) that replace the kernel's normal ICMP emission when BPF bypasses the host stack.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## VXLAN in eBPF mode

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
in [bpf-conntrack-flowstate.md → Switching from `*tables` to eBPF](./bpf-conntrack-flowstate.md), which handles flows whose conntrack was in `*tables` rather
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




## IP fragmentation

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




## BPF-synthesised ICMP errors

### Why BPF needs to synthesise them

When BPF forwards a packet with `bpf_redirect*` or decides to drop
one, the kernel's IP stack is bypassed — and with it, the kernel's
ordinary ICMP-error emission. Without an explicit BPF replacement,
common network diagnostics would silently break:

- **TTL-exceeded** — `traceroute` and `mtr` would stop working on
  BPF-forwarded paths because the forwarder never sent the expected
  ICMP Time Exceeded.
- **Fragmentation needed (IPv4) / Packet too big (IPv6)** — Path
  MTU Discovery would fail for paths that cross a smaller-MTU next
  hop, because BPF either cannot fragment the packet itself or has
  intentionally grown it (e.g. VXLAN encap, reassembled defrag)
  past the MTU and has no kernel stack behind it to emit the
  needed message.
- **Other protocol-necessary errors** (port unreachable, etc.)
  where the BPF-mediated path would otherwise just silently drop.

### Implementation

ICMP error generation lives in `felix/bpf-gpl/icmp.h`,
`icmp4.h` (IPv4 `icmp_v4_reply`) and `icmp6.h` (IPv6
`icmp_v6_reply`). The main TC program uses the `icmp_too_big`
label and similar entry points; the actual packet-building runs
in a dedicated sub-program, **`calico_tc_skb_send_icmp_replies`**
(registered as the `ICMP`-class sub-program in
`felix/bpf/hook/map.go`).

Building an ICMP error requires:

- Capturing enough of the offending packet (L3 header + 64 bits of
  the L4 header by convention) as the ICMP payload.
- Assembling the outer headers (IPv4 or IPv6, with the local
  address as source and the original source as destination).
- Computing the correct ICMP checksum; for IPv4 the IP header
  checksum needs updating too.

This is non-trivial work that would make the main program too large
for the verifier, and most packets never need it. Splitting ICMP
error generation into its own sub-program keeps the fast path
small — the main program only tail-calls into it on the rare path
where an error is actually needed.

### Cases

- **TTL exceeded.** `ip_ttl_exceeded` in `bpf.h` tests for TTL==1
  (IPv4) / hop-limit==1 (IPv6) on a host-egress path. If that
  holds and the packet would have been forwarded, the program
  generates an ICMP Time Exceeded and drops the packet instead.
- **Too big after encap / defrag.**
  `vxlan_encap_too_big` and similar checks in `tc.c` compare the
  projected post-encap size against the next-hop MTU; on too-big
  the program jumps to `icmp_too_big` and generates ICMP
  frag-needed (v4) / packet-too-big (v6) with the right MTU value.
- **Post-defrag too big.** After reassembling fragments (IP fragmentation),
  the result may exceed the next-hop MTU; same ICMP path.

### Relation to fast-path discipline ([bpf-overview.md → Fast-path performance discipline](./bpf-overview.md))

ICMP error generation is explicitly a **slow path**. The main
program decides to generate one only on conditions that should be
rare in normal operation (TTL exhaustion, PMTU mismatch); the work
happens in a tail-called sub-program, not inline. Expensive work
here is acceptable.

### Review notes

- A change that introduces a new BPF-side drop on a forwarded
  packet should explicitly decide: silent drop, or ICMP-error?
  Silent drops in a BPF-forwarded path are invisible to the
  sender in a way they would not be in a `*tables` path.
- A new encapsulation that grows packets needs a too-big check
  on the encap path and a jump to `icmp_too_big` with the
  correct MTU — otherwise PMTU discovery breaks for that
  encapsulation.
- Any change to the ICMP sub-program has to preserve the
  checksum pipeline (`bpf_l3_csum_replace`,
  `bpf_l4_csum_replace`). Broken checksums fail silently at the
  receiver.
- The ICMP sub-program is registered per-attach-type in
  `felix/bpf/hook/map.go` — a change to when it is applicable
  (e.g. disabling it for a new attach type) must go through
  `GetApplicableSubProgs`.




---

## Keep this doc in sync with the code

A change to how the BPF dataplane works in the area this file
covers must update the relevant section in the same PR — new
mechanism, new flag, new map field, new config knob, or any
change to the packet path. Exemptions: (a) bug fix restoring
documented behaviour, (b) mechanical refactor with no observable
change, (c) comment / log-message edits, (d) dependency bumps.
If in doubt, update.

Cross-cutting rules that apply to **every** BPF change (map
versioning, mark discipline, sub-program registration, kernel-
version sensitivity) live in
[`bpf-overview.md` → Cross-cutting review notes](./bpf-overview.md).
