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

# Neighbour discovery — proxy ARP and proxy NDP

How Felix makes workload IPs resolvable by ARP and NDP: the
workload-facing `proxy_arp` / `proxy_ndp` sysctls, the fabric-facing
userspace proxy-neighbour responder, why the IPv4 and IPv6 stories are
deeply asymmetric, and how each interacts with VM live migration.

The dataplane architecture these managers sit in — the manager/driver
split, the `OnUpdate` / `CompleteDeferredWork` contract, dual-stack
instantiation — is in [`dataplane.md`](./dataplane.md). The full set of
sub-designs is listed in [`felix/DESIGN.md`](../DESIGN.md).

## Two mechanisms, easily conflated

Calico answers neighbour-discovery requests in two unrelated places,
for two unrelated reasons. Keep them apart:

| | Workload-facing | Fabric-facing |
|---|---|---|
| What | `proxy_arp` / `proxy_ndp` sysctls, per workload interface | userspace raw-socket listener on host NICs |
| Code | `endpoint_mgr.go` → `configureInterface` | `proxy_neigh_mgr.go` (the "proxy neighbour manager", PNM) |
| Answers requests from | the local workload | the fabric outside the node |
| Answers for | whatever the host has a route to (the kernel decides) | pod and LoadBalancer IPs that fall inside a host NIC's subnet |
| Why | let the guest/pod reach everything without per-workload subnet plumbing | make an IP drawn from a host-NIC subnet reachable without extra BGP |

The fabric-facing responder does **not** replace the sysctls, and the
two are not alternative implementations of one feature. A change to one
says nothing about the other.

PNM exists so that a workload IP taken from a host NIC's subnet is
reachable from outside the cluster without additional BGP: if the host
subnet is already reachable, answering ARP/NDP for the workload IP on
that subnet is enough. Its original driver was egress gateways;
LoadBalancer service IP support came later.

### Review notes for this section

- Requests arriving *from a workload* and requests arriving *from the
  fabric* are different problems. Before adding neighbour-discovery
  behaviour, state which direction it serves; a fix in the wrong place
  will look plausible and do nothing.
- PNM only ever answers for IPs that are both in a no-encap IP pool
  (`isInNoEncapPool`) and inside the subnet of some host interface
  (`addMatchingIPs`). Outside that intersection it is inert, so PNM is
  never the explanation for ordinary pod reachability.

## Workload-facing: why IPv4 needs proxy ARP

For OpenStack, guest networking must be configured by DHCP, and DHCP
requires a subnet and a gateway. Representing a Calico network in the
natural way would burn addresses — a distinct /30 per guest. Instead
the whole pool is advertised to the guest as its subnet and the host
answers ARP for every address in it, routing the traffic on whether or
not it is really on-subnet. For containers the motivation is smaller:
routes inside the pod's namespace use a link-local gateway address, and
proxy ARP means that address need not be assigned to each veth.

The kernel's `proxy_arp` is **route-based**: on receiving a request the
kernel performs a forwarding route lookup for the request's source and
target, and replies with its own MAC if the target resolves to a
unicast route out of a *different* interface than the one the request
arrived on (`arp_process` / `arp_fwd_proxy`, gated on forwarding being
enabled). Felix does not enumerate the addresses it will answer for —
the routing table decides, request by request.

That generality is what makes the live-migration suppression below
necessary: whenever a peer node holds an off-box route for a workload's
own IP, the kernel will happily answer the workload's request for its
own address.

### Review notes for this section

- `proxy_arp` answers for addresses Felix never enumerated. When
  reasoning about what a node will answer for, read the *routing
  table*, not a list in Felix.
- The reply also depends on the request's source being routable, so
  proxy-ARP behaviour can change as a side effect of route changes that
  look unrelated.

## Workload-facing: why IPv6 needs nothing

`net.ipv6.conf.<iface>.proxy_ndp` is **not** the IPv6 spelling of
`proxy_arp`. It does no route-based proxying: the kernel answers a
Neighbor Solicitation only when an explicit proxy neighbour entry
(`NUD_PROXY`, i.e. `ip -6 neigh add proxy <addr> dev <iface>`) exists
for the solicited target. Calico creates no such entries anywhere —
the only neighbour entries it programs are `NUD_PERMANENT` ones
(`routetable/route_table.go`, `vxlanfdb/`, `bpf_ep_mgr.go`).

So the `proxy_ndp=1` that Felix (`endpoint_mgr.go`) and the CNI plugin
(`cni-plugin/pkg/dataplane/linux/dataplane_linux.go`) set on workload
interfaces is **inert**. It is harmless, and would become load-bearing
only if we ever started programming proxy entries.

IPv6 does not need it, because the guest is never told that anything is
on-link:

- **OpenStack.** The DHCP agent runs dnsmasq with `--enable-ra`, and
  rewrites every IPv6 `--dhcp-range` to add `off-link`
  (`networking-calico/networking_calico/agent/linux/dhcp.py`), so the
  pool prefix is advertised without the on-link flag. DHCPv6 conveys no
  prefix length, so the address the guest receives is effectively a
  /128. The guest therefore has *no on-link prefix except link-local*:
  the pool prefix arrives as a route **via the router**, not as a
  connected subnet. Everything — including traffic to other VMs in the
  same pool — goes to the compute host's link-local address, which the
  host answers for as its own address, no proxying involved.
- **Containers.** Same shape. The pod's IPv6 default route uses the host
  end of the veth's link-local address as its gateway
  (`hostSideMACAsIPv6LL`, derived from the fixed `ee:ee:ee:ee:ee:ee`
  veth MAC), again the host's own address, and the pod's own address is
  a /128, so again nothing but link-local is on-link.

### What the guest and pod actually see

An OpenStack guest (from a smoke-test console dump; the gateway
link-local address is derived from the tap's fixed `DEFAULT_TAP_MAC`,
`00:61:fe:ed:ca:fe`):

```
if-info: eth0,up,10.28.0.57,17,fe80::f816:3eff:feab:f824/64,fd5f:5d21:845:1c2e:2::337/128
ip-route :default via 10.28.0.1 dev eth0 src 10.28.0.57 metric 1002
ip-route :10.28.0.0/17 dev eth0 scope link src 10.28.0.57 metric 1002
ip-route6:fd5f:5d21:845:1c2e:2::/80 via fe80::261:feff:feed:cafe dev eth0 metric 1002
ip-route6:fe80::/64 dev eth0 metric 256
ip-route6:default via fe80::261:feff:feed:cafe dev eth0 metric 1002
```

The two families in one guest are the whole argument for this doc. The
IPv4 pool is **on-link** (`10.28.0.0/17 dev eth0 scope link`), so the
guest ARPs for every address in it and the host must proxy-ARP. The IPv6
pool is reachable **via the router** (`.../80 via fe80::261:...`), so
the guest never solicits a peer VM's address at all.

A Kubernetes pod, dual-stack, no explicit routes configured (asserted
in `cni-plugin/tests/calico_cni_k8s_test.go`, which runs real
containers):

```
default via 169.254.1.1 dev eth0
169.254.1.1 dev eth0 scope link
dead:beef::<n> dev eth0 proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::ecee:eeff:feee:eeee dev eth0 metric 1024
```

Again asymmetric, and again in Calico's favour on the IPv6 side.
`169.254.1.1` is a dummy gateway that is *not* assigned to the host end
of the veth, so it resolves only because proxy ARP answers for it —
that is the container-side reason the sysctl is needed. The IPv6
gateway `fe80::ecee:eeff:feee:eeee` **is** a real address on the host
end (auto-generated from its fixed MAC), so it resolves by ordinary
NDP. Where the CNI config does request routes, they too appear `via`
that gateway (`dead:beef::/96 via fe80::ecee:...`) rather than on-link.

The IPv4 subnet trick and the IPv6 RA arrangement solve the same
problem by different means. IPv6 did not abandon proxying so much as
never need it.

The practical consequence: **an IPv4 workaround that constrains proxy
ARP has no IPv6 counterpart to write.** This is the resolution of
CORE-12498, which asked whether the live-migration ARP suppression
below needed an NDP equivalent. It does not.

### How to verify the kernel behaviour

Both claims above are reproducible in a pair of network namespaces
joined by a veth, with the "host" side holding an off-box route for the
address being probed:

- IPv4, `proxy_arp=1`, no static entries: the host answers, and the
  probing workload ends up with a neighbour entry pointing at the
  host's MAC.
- IPv6, `proxy_ndp=1`, no proxy entry: no answer. Add
  `ip -6 neigh add proxy <addr> dev <host-side>` and the answer
  appears.

Note that the IPv4 case needs a route back to the request's source
before the kernel will reply at all (see the previous section).

### Review notes for this section

- Do not "add the missing IPv6 half" of a proxy-ARP mechanism without
  first establishing that a `NUD_PROXY` entry exists for the target.
  Absent such entries, an NDP-side change cannot have any effect.
- If Calico ever does start programming proxy neighbour entries, this
  section and the live-migration suppression below both need
  revisiting: the IPv6 path would acquire the same failure mode IPv4
  has today.
- Changes to the OpenStack DHCP agent's RA or `off-link` handling, or
  to the CNI plugin's link-local gateway, change the premise of this
  whole section. Update it in the same PR.

## Live migration and the workload-facing path

During a VM live migration the same workload IP exists on two nodes,
and a node other than the one currently running the VM holds a route
for that IP pointing off-box. Kernel proxy ARP will then answer the
VM's own ARP request for its own address with the host's MAC, poisoning
the guest's neighbour table.

Felix suppresses that with a small nftables `arp`-family table: per
workload, a chain (`rules.WorkloadARPPfx`, reached from the
`cali-arp-dispatch` chain in the `calico-arp` table) drops ARP
*replies* leaving the workload interface whose ARP source address is
one of the workload's own IPs — `updateWorkloadARPChains` in
`endpoint_mgr.go`.

Two things worth knowing:

- It is gated on the `NFTablesSupported` *feature* — whether nftables
  is usable at all — not on nftables *mode*. Where the kernel lacks
  nftables support, the suppression is simply absent.
- It is IPv4-only, and correctly so: per the section above there is no
  IPv6 mechanism to suppress. The `nil` arpTable passed to the IPv6
  endpoint manager is deliberate, not an oversight.

The *route* side of live migration — suppression on the migration
target, elevated route priority after cutover, and propagation of that
priority to peers as BGP LOCAL_PREF — is a separate mechanism, not yet
covered by a sub-design.

### Review notes for this section

- The ARP suppression is per-family by necessity, not by symmetry. Do
  not "fix" the IPv6 endpoint manager's `nil` arpTable.
- Anything else that becomes per-family *by accident* is a bug: the
  live-migration route logic is reached through a listener registered
  once per endpoint manager, and registering it for only one family
  silently disables suppression and priority elevation for the other
  (CORE-12806).

## Live migration and the fabric-facing responder — known gap

PNM answers ARP and NDP on host NICs, sends gratuitous ARPs and
unsolicited neighbour advertisements when it takes ownership of an IP,
answers IPv6 DAD probes, and re-announces periodically. For pod IPs the
hosting node always answers; for LoadBalancer VIPs a consistent hash
ring picks a single answering node.

Its live-migration handling is **not** wired to the migration state
machine. It gates directly on the role carried on the workload
endpoint — answer unless this endpoint is the migration `SOURCE`
(`proxy_neigh_mgr.go`) — whereas the route logic switches on the
GARP/RARP-driven FSM that detects actual cutover. The resulting
sequence is:

1. Before migration: the source node answers.
2. Migration starts; the source's endpoint is marked `SOURCE` but the
   target's endpoint may not be programmed yet — briefly, *nobody*
   answers.
3. The target's endpoint is programmed, but the VM is still running on
   the source: the **target** answers, though it is not yet the active
   node.
4. Cutover happens; the target answers, which is now correct.
5. Migration completes and the source endpoint is cleaned up.

Step 3 is the wrong window, and step 2 a smaller one. Whether a
mid-migration handover would even be safe to do precisely is unknown:
it is not established that two nodes answering for the same IP is
harmful (both would return the VM's MAC), and there is at least one
known case of a confusing ARP response costing a guest ~10s of
connectivity.

Doing better is genuinely hard. There is no synchronisation primitive
between the two nodes: the L3 design deliberately avoids needing one,
because two routes to the same IP may coexist at different priorities,
so nothing has to happen on the source at the moment the target starts
advertising. Neighbour discovery has no equivalent "both at once, one
preferred" state.

There is a second failure mode: if a migration stalls and never
completes, PNM keeps directing traffic to the target — which never
becomes active — until the stuck target endpoint is removed by hand.

**Status: understood, deliberately deferred.** PNM plus live migration
is not a supported combination today; the intent is to revisit it in a
later phase of PNM development, at which point PNM would need to
observe live-migration state rather than the raw role. Until then this
gap is documented rather than fixed.

### Review notes for this section

- Do not change the role-based gate in isolation. Inverting it (source
  answers, target does not) moves the wrong window rather than closing
  it; closing it properly requires deciding the handover story first.
- A PR that makes PNM observe live-migration FSM state is a design
  change to both features: update this section and the live-migration
  route behaviour together.
- If PNM gains support for IPs outside no-encap pools or outside host
  NIC subnets, the "PNM is inert here" assumption in the first section
  stops holding.

---

## Keep this doc in sync with the code

A change to how Calico answers ARP or NDP must update the relevant
section in the same PR: a new sysctl on workload interfaces, a change
to what PNM answers for or where it listens, a change to the
live-migration ARP suppression, or any move towards programming proxy
neighbour entries. Changes outside Felix that this doc depends on — the
OpenStack DHCP agent's RA and `off-link` handling, the CNI plugin's
link-local gateway or `proxy_ndp` setting — count too.

Exemptions: (a) a bug fix restoring behaviour this doc already
describes, (b) a mechanical refactor with no observable change,
(c) comment or log-message edits, (d) dependency bumps. If in doubt,
update.
