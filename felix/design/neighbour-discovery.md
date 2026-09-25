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
workload-facing `proxy_arp` sysctl, the fabric-facing userspace
proxy-neighbour responder, why the IPv4 and IPv6 stories are deeply
asymmetric, and how each interacts with VM live migration.

The dataplane architecture these managers sit in — the manager/driver
split, the `OnUpdate` / `CompleteDeferredWork` contract, dual-stack
instantiation — is in [`dataplane.md`](./dataplane.md). The full set of
sub-designs is listed in [`felix/DESIGN.md`](../DESIGN.md).

## Two mechanisms, easily conflated

Calico answers neighbour-discovery requests in two unrelated places,
for two unrelated reasons. Keep them apart:

|                       | Workload-facing                                                         | Fabric-facing                                                       |
|-----------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------|
| What                  | `proxy_arp` sysctl, per workload interface                              | userspace raw-socket listener on host NICs                          |
| Code                  | `endpoint_mgr.go` → `configureInterface`                                | `proxy_neigh_mgr.go` (the "proxy neighbour manager", PNM)           |
| Answers requests from | the local workload                                                      | the fabric outside the node                                         |
| Answers for           | whatever the host has a route to (the kernel decides)                   | pod and LoadBalancer IPs that fall inside a host NIC's subnet       |
| Why                   | let the guest/pod reach everything without per-workload subnet plumbing | make an IP drawn from a host-NIC subnet reachable without extra BGP |

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

In OpenStack, guest networking is configured by DHCP.  DHCP tells the
guest VM its IP, subnet and gateway, which means the guest gets a
routing table like this:

```
default via <gateway>
<subnet> dev eth0
```

and the guest _thinks_ it is directly connected to any IP within the
`<subnet>` (including `<gateway>`, which must be within `<subnet>`).
Hence, for any outbound connection, the next hop IP must be within
`<subnet>` and the guest will ARP for that next hop IP.

Calico configures `proxy_arp` on each workload interface so that the
host responds to that ARP, saying "yes, that's me".  For IPv4 this
process only depends on the next hop IP (i.e. what the ARP asks for)
being routable in the host's routing table.  That allows outbound
traffic to reach the host, then the host routes onward according to its
own routing table.

(If we didn't use `proxy_arp`, we'd instead need to tell the guest that
it was on a /31 subnet, containing only its own IP and a host IP, and
assign that host IP on the host side of the workload's TAP interface.
That is technically a more accurate representation of the actual
networking, but it would mean using up two IPv4 addresses for every
workload instead of just one.  So we don't do that.)

In Kubernetes, our CNI plugin sets up the routing table inside the pod,
and it looks like this:

```
default via 169.254.169.1
169.254.1.1 dev eth0 scope link
```

Then any outbound traffic involves an ARP request for 169.254.169.1, and
`proxy_arp` on the host side does the same job to respond to that as in
the OpenStack case.

(169.254.169.1 is a "link-local" address, but that's not relevant to how
ARP and `proxy_arp` work.)

### Review notes for this section

- `proxy_arp` answers for addresses Felix never enumerated. When
  reasoning about what a node will answer for, read the *routing
  table*, not a list in Felix.
- The reply also depends on the request's source being routable, so
  proxy-ARP behaviour can change as a side effect of route changes that
  look unrelated.

## Workload-facing: why IPv6 needs nothing

The root of the asymmetry is **address provisioning, not proxying**.
Linux gives every interface an IPv6 link-local address automatically, so
the host side of a workload interface — veth for Kubernetes, tap for
OpenStack — always has an address the workload can use as its next hop,
and the host answers NDP for it as *its own* address.  The VM or pod
routing table then uses this real IPv6 link-local address:

- on OpenStack:

  ```
  fe80::/64 dev eth0 metric 256
  default via fe80::261:feff:feed:cafe dev eth0 metric 1002
  ```

- on Kubernetes:

  ```
  fe80::/64 dev eth0 proto kernel metric 256 pref medium
  default via fe80::ecee:eeff:feee:eeee dev eth0 metric 1024
  ```

No NDP proxying is involved, because `fe80::261:feff:feed:cafe` and
`fe80::ecee:eeff:feee:eeee` are real link-local IPv6 addresses that are
actually provisioned on the host side of workload interfaces.

Calico therefore **does not set `proxy_ndp`** on workload interfaces.

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

**Status: understood, deliberately deferred — tracked as CORE-13246.**
PNM plus live migration is not a supported combination today; the intent
is to revisit it in a later phase of PNM development, at which point PNM
would need to observe live-migration state rather than the raw role.
Until then this gap is documented rather than fixed.

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
