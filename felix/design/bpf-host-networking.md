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

# eBPF dataplane — Host-networked workaround (bpfnat veth)

How host-networked services reach BPF when CTLB is off: the `bpfin.cali` / `bpfout.cali` veth pair, the routing trick that pulls host-origin service traffic through it, the tunnel-trouble narrative, the RPF sysctls the feature requires, and the NodePort-turnaround edge cases.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## Host-networked workaround (bpfnat veth)

### Why it exists

CTLB ([bpf-services.md → Connect-Time Load Balancer (CTLB)](./bpf-services.md)) resolves services at `connect(2)` time for applications that
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
  `BPFHostNetworkedNATWithoutCTLB = Enabled`.
- **UDPOnly** — hybrid: CTLB handles TCP, bpfnat handles UDP. Selected
  indirectly by `BPFConnectTimeLoadBalancing = TCP`, which leaves UDP
  to the slower but safer per-packet path so connected-UDP
  applications don't get stuck on a dead backend ([bpf-services.md → Connect-Time Load Balancer (CTLB)](./bpf-services.md)). This mode is
  a compromise between the CTLB performance win and UDP correctness.

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
- The `CALI_SKB_MARK_MASQ` / `CALI_SKB_MARK_NAT_OUT` marks ([bpf-overview.md → Packet path overview](./bpf-overview.md)) steer
  packets to `*tables` SNAT when needed.

A previously-considered alternative — doing SNAT in BPF, allocating
host source ports from BPF — was rejected because BPF cannot safely
coordinate port allocation with the kernel's socket tables. The
pragmatic compromise is port-only SNAT with random-port retry on
collision (same technique used for external-NodePort conflict; [bpf-services.md → External traffic (NodePort, DSR)](./bpf-services.md)).

### RPF requirements

Routing host service access through the veth means that some packets
travel through the system via routes the kernel wouldn't normally
expect. The host-side sysctl requirements (enforced by
`setRPFilter("all", 0)` in `bpf_ep_mgr.go` when the feature is
enabled) are:

- `net.ipv4.conf.all.rp_filter = 0`. Any non-zero value on `all`
  trumps the per-interface setting.
- Per-interface: `rp_filter = 0` (off; BPF enforces RPF itself,
  see [bpf-conntrack-flowstate.md → Reverse-path filter (RPF)](./bpf-conntrack-flowstate.md)), `accept_local = 1` (the veth round-trip produces a
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
