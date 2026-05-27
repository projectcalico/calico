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

# eBPF dataplane — Service NAT, load balancing, CTLB

How the BPF dataplane resolves Kubernetes services: intra-cluster (cali* veth) and external (NodePort, DSR) traffic paths, Maglev consistent-hash backend selection for LB-fronting nodes, session affinity (`cali_v?_nat_aff`), the BPF kube-proxy replacement (`felix/bpf/proxy/`), and the connect-time load balancer (CTLB) attached to cgroup hooks.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## Intra-cluster traffic & service NAT

### The common case: pod to service

> **Note.** Everything in this subsection describes the TC path.
> When CTLB (Connect-Time Load Balancer (CTLB)) is enabled, a pod's service traffic never takes
> this path: CTLB rewrites the destination at `connect(2)` time and
> the TC program on `cali*` only ever sees pod→pod packets with the
> backend's address. The TC path below applies when CTLB is
> disabled for the traffic in question (raw sockets always, UDP if
> `BPFConnectTimeLoadBalancing = TCP`, any traffic if CTLB is off
> entirely).

When a pod sends a packet to a service IP, the packet leaves the pod
and enters the host on the pod's host-side veth (`cali*`). The TC
program on that veth — attached to the TC ingress hook on the
host-side (host-ingress from the host's point of view, policy
_egress_ from the pod's) — runs first.

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
   conntrack entries ([bpf-conntrack-flowstate.md → Conntrack & cleanup](./bpf-conntrack-flowstate.md)): a forward entry keyed on the pre-NAT
   tuple, and a reverse entry keyed on the post-NAT tuple. The reverse
   entry is what lets return packets (backend → pod) be matched and
   un-NATed without another NAT lookup.

On subsequent packets, the forward entry is hit first and there is no
need to re-resolve the service. Return packets hit the reverse entry
and have the service frontend IP/port restored on the way back to the
pod.

### Same host — the fast-path shortcut

When the selected backend is on the same host, the dataplane can
take a significantly shorter path than `*tables` does. After DNAT
and policy, the BPF program looks up the backend's veth via the
ifstate map and, on established-flow packets, hands the packet
directly to the backend's pod side with `bpf_redirect_peer`. The
packet never touches the host FIB, never enters the host netfilter
chains, and does not trigger the host-side program of the backend's
veth — the pod receives it straight from its own side of the veth.

`fib_approve` ([bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md)) is the gate: it checks that the backend's
interface is ready (attach-gap protection) and whether the flow is
confirmed in conntrack; unconfirmed traffic is fallthrough'd to the
host stack so the `*tables` drop rules apply.

Review note: a change that forces the same-host path through the
host stack is a measurable regression. The shortcut is not optional
under BPF mode; it's the point of running BPF for this case.

### Pod-service-self (no CTLB)

When the backend chosen for a service is the pod that originated
the traffic, this would naively resolve to a self-to-self packet.

With CTLB on, the destination rewrite happens inside `connect(2)`
and the socket pair is set up pod-to-pod-same-address. No packet
is ever emitted on the network — a substantial deviation from
`*tables`, where every pod-service-self packet makes a MASQ
round-trip through the host. This is one of the reasons CTLB is
an important performance feature (Connect-Time Load Balancer (CTLB)).

Without CTLB, the host would have to loop the packet back, which
fails: `accept_local` is `0` by default on the pod's veth, and no
socket exists for the `(self, self)` 5-tuple anyway. Calico handles
this the same way kube-proxy does — it relies on `*tables` MASQ to
change the source so the packet looks like it came from the host
and the pod accepts it.

The signal is carried on the conntrack entry:

- On the host-ingress program of the pod's veth, if the source IP
  equals the post-NAT destination IP, the program sets
  `CALI_CT_FLAG_SVC_SELF` on the new NAT-reverse entry (see
  `conntrack_types.h` and the NAT-create path in `tc.c`).
- On the way out after policy allow, if that flag is set on the flow,
  `CALI_SKB_MARK_MASQ` is set on the packet and FIB is disabled. The
  packet falls through to `*tables`, which MASQ-SNATs it.
- On the return leg (host-egress toward the pod, `CALI_F_TO_WEP`),
  the program detects the `CALI_SKB_MARK_MASQ` mark and restores
  the saved original source so the CT reverse-match works.

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




## External traffic (NodePort, DSR)

### NodePort: happy path

An external client opening a connection to a NodePort lands on the
node's main cluster interface (a HEP). The TC HEP-ingress program
runs:

1. Look up the `(local-host-IP, dst-port, proto)` tuple in the NAT
   frontend map. If the service exists, pick a backend.
2. If the chosen backend is a **local** pod, DNAT the packet and
   forward it to the pod's host-side veth as in Intra-cluster traffic & service NAT.
3. If the chosen backend is on a **remote** node, wrap the packet in a
   VXLAN header ([bpf-encap-fragments-icmp.md → VXLAN in eBPF mode](./bpf-encap-fragments-icmp.md)) with the destination being the node that hosts
   the backend, and hand it to the host stack to route out. The
   packet is marked "seen/approved" so Calico's egress HEP does not
   re-run policy on it.

> **VXLAN ambiguity — worth flagging for readers.** The VXLAN used
> here for NodePort forwarding is a separate use of the VXLAN
> device from the pod-to-pod VXLAN overlay. Calico programs both on
> the same `vxlan.calico` device (flow-mode, see [bpf-encap-fragments-icmp.md → VXLAN in eBPF mode](./bpf-encap-fragments-icmp.md)), but:
>
> - **NodePort-forwarding VXLAN** (this step) is always present in
>   BPF mode, regardless of whether the overlay uses VXLAN, IPIP,
>   WireGuard, or no encap. It carries external traffic that has
>   hit a NodePort on a node whose selected backend is on a
>   different node. It uses a fixed VNI of **`0xca11c0`**
>   (`CALI_VXLAN_VNI` in `felix/bpf-gpl/nat.h`) — reserving that
>   value so receivers can tell NodePort-forwarding packets from
>   overlay packets on the same device.
> - **Pod-to-pod overlay VXLAN** is what pod→pod traffic uses when
>   the cluster's overlay is configured as VXLAN. Its VNI is the
>   operator-configured overlay VNI, not `0xca11c0`.
>
> A reader familiar with the overlay may assume one implies the
> other; it doesn't. The BPF program picks per-packet which
> semantics apply and sets the VXLAN tunnel key (destination
> node IP + VNI) accordingly.

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

The return path follows the forward path as a deliberate choice:
in non-DSR mode the ingress node holds the conntrack reverse entry
keyed on the original client tuple, and returning packets there
lets a single un-NAT restore the service-IP source seen by the
client. DSR mode is the alternative — the backend node SNATs the
return packet itself, so no round-trip to the ingress node is
needed (see below).

### DSR

With DSR enabled, return traffic does _not_ go back through the
ingress node. The backend node simply SNATs the return packet
(swapping the backend IP for the ingress-node IP so the packet
looks like it came from the service) and lets the network deliver
the packet directly to the client.

DSR requires asymmetric-path tolerance in the underlay — and not
just at the client. Every hop between the backend node and the
client must accept an inbound packet from a node other than the one
the forward packet was routed to. Cloud underlays and carefully-
configured switched fabrics are typically fine; setups with strict
uRPF on the first hop are not. The client's distance from the
cluster often hides the asymmetry from the client itself, but the
local network between the cluster and the first common hop must be
accepting of it.

The cluster admin opts in via `BPFExternalServiceMode = dsr` (vs.
the default `tunnel`) with `BPFDSROptoutCIDRs` for per-destination
opt-out. DSR is also a prerequisite for Maglev (Maglev load balancer).

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

An external load balancer in front of the cluster holds connections
to several nodes at the same time. From the LB's point of view each
`(LB-IP, src_port) → (node-IP, dst_port)` 4-tuple is unique, so the
LB can legitimately reuse the _same_ source port against different
node IPs: the distinct destinations make the 4-tuples distinct.

The collision appears **after DNAT**. Each node DNATs the incoming
packet from `(node-IP, node-port)` to the chosen backend pod. If
multiple of these formerly-distinct destinations resolve to the
same backend pod, the post-DNAT flows all look like
`(LB-IP, src_port) → (backend-IP, backend-port)` — identical 5-tuples
that were different connections when the client originally made them.
Without intervention they collide on the backend pod's conntrack.

Calico resolves this with port-SNAT on the ingress node: on
collision the TC program picks a random source port from a
reserved range (`PSNATStart`/`PSNATEnd` on the attach point) and
retries. The resulting tuple is stable for the lifetime of the
flow because the CT entry records it.

Changes to this logic need to preserve port stability within a
flow — return packets must still match the CT entry.

### Review notes for this section

- A change to the NodePort lookup path must not break the wildcard
  (`255.255.255.255` / all-ones IPv6) fallback used for pods
  addressing a NodePort via a node IP. The wildcard entry lives in
  the same NAT frontend map as regular entries; changes to the key
  layout need to respect both.
- A change to DSR gating must still compile-time-assert
  `CALI_F_DSR` only with `CALI_F_FROM_WEP` or `CALI_F_HEP`
  (see the `COMPILE_TIME_ASSERT` in `felix/bpf-gpl/bpf.h`). DSR
  makes no sense on WEP ingress.




## Maglev load balancer

> **Relationship to External traffic (NodePort, DSR).** Maglev layers on top of the NodePort
> VXLAN-forwarding path described in External traffic (NodePort, DSR). The forwarding mechanics —
> VXLAN-wrap to the backend node, DSR return, conntrack bookkeeping
> — are reused unchanged. What Maglev adds is consistent-hash
> backend selection in place of the usual per-node random/round-robin,
> plus a re-run of policy on mid-flow packets that may have failed
> over from another lb-node.

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
see [bpf-conntrack-flowstate.md → Switching from `*tables` to eBPF](./bpf-conntrack-flowstate.md)) or dropped as unsolicited. Maglev adds a third class: a
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
- **CTLB.** The connect-time LB (Connect-Time Load Balancer (CTLB)) resolves the service at syscall
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




## Service session affinity

### What it is

Kubernetes Services can opt into **client-IP affinity** by setting
`sessionAffinity: ClientIP`. While the affinity is valid, the same
client IP talking to the same service is pinned to the same backend
pod. Applies to all service types — ClusterIP, NodePort, LoadBalancer,
external or intra-cluster; any path that does BPF backend selection.

### How the BPF dataplane implements it

A dedicated map,
**`cali_v4_nat_aff`** / **`cali_v6_nat_aff`**
(`felix/bpf/nat/maps.go`, `maps6.go`; sized via
`BPFMapSizeNATAffinity`), records the affinity:

- Key: `(service_id, client_IP)`.
- Value: `(backend, last_used)`.

Backend selection for a **new flow** (no BPF conntrack hit) runs:

1. Look up `(service_id, client_IP)` in the affinity map.
2. If there is a valid (unexpired, and backend still in service) hit,
   use that backend.
3. Otherwise pick a backend by the service's normal algorithm
   (round-robin, Maglev, etc.) and populate the affinity entry.

The CT entry created for the flow carries the chosen backend, so
per-packet forwarding does not revisit the affinity map. The affinity
map's `last_used` is updated opportunistically on new-flow backend
resolution; flow-lifetime fast-path packets are not affected.

### Applicability

- Works for both the TC path and the CTLB path: CTLB's connect-time
  backend pick also consults the affinity map before calling the
  normal selection algorithm.
- Interacts with Maglev: if a Maglev service also has
  `sessionAffinity=ClientIP`, the affinity check runs first. The
  Maglev consistent-hash is only reached when there is no affinity
  entry.
- Interacts with `externalTrafficPolicy=Local`: affinity only pins
  to an eligible backend; if the previously-pinned backend is no
  longer eligible (policy excluded it), the entry is re-resolved.

### Review notes

- A change to the service-backend selection sequence must keep
  affinity lookup _before_ the main selection algorithm. Affinity
  is the authoritative answer when it applies; moving it later
  turns sessionAffinity into a cache rather than a guarantee.
- A change to the affinity map's key/value layout needs a map
  version bump **only** if the change makes new programs
  incompatible with the old map ([bpf-overview.md → Cross-cutting review notes](./bpf-overview.md)). Reusing reserved bytes for
  a new field doesn't need a bump.
- An affinity entry that points at a backend that no longer exists
  must be treated as a miss, not as a drop. A change that tightens
  the "is backend still valid" check must preserve that.




## Service syncing & the BPF kube-proxy replacement

### Role

`felix/bpf/proxy/` is Calico's in-Felix replacement for kube-proxy.
It watches Kubernetes Service, Endpoints and EndpointSlice resources
and translates them into the BPF maps that the TC programs
([bpf-xdp.md → XDP programs and the XDP→TC handoff](./bpf-xdp.md)–Maglev load balancer) and the CTLB (Connect-Time Load Balancer (CTLB)) read. When BPF mode is on, Calico
disables kube-proxy and takes full responsibility for service
implementation.

This is the userspace half of "service NAT" — the TC-side view
(Intra-cluster traffic & service NAT–External traffic (NodePort, DSR)) only sees "a map with a frontend pointing at a backend".
The proxy package is what fills those maps, keeps them consistent
as Services/Endpoints churn, and applies the Kubernetes
semantics (topology, traffic policies, health, affinity) before
the BPF program ever runs.

### Components

- **`syncer.go`** — the central syncer. Diffs the desired state
  (from watchers) against the current state (from the BPF maps)
  and applies the delta. Handles frontend, backend, affinity and
  Maglev LUT maps.
- **`kube-proxy.go`** — the Kubernetes-facing layer. Reads
  Services, Endpoints, EndpointSlices; translates them into the
  syncer's internal model.
- **`topology.go`** — implements topology-aware routing
  (`topologyAwareHints`, `preferClose`, etc.). Filters backends
  based on the node's zone/region.
- **`health.go`** — NodePort / LoadBalancer health checks for
  services with `externalTrafficPolicy=Local`; tells external
  load-balancers which nodes to avoid.
- **`lb_src_range.go`** — handles `loadBalancerSourceRanges` ACLs
  for LoadBalancer services.
- **`rtcache.go`** — routing-table cache used by topology
  decisions.
- **`proxy.go` / `proxy_test.go` / `options.go`** — the driver
  plumbing.

### Maps it owns

(All under `felix/bpf/nat/`.)

- Frontend map — `(service-IP, port, proto) → service_id`.
- Backend map — `(service_id, ordinal) → (backend_IP, port)`.
- Affinity map — see Service session affinity.
- Maglev LUT — see Maglev load balancer.
- Reverse-SNAT map (`cali_v4_srmsg` / `cali_v6_srmsg`) — used by
  the CTLB's `recvmsg` hook to undo destination rewrites.

### Semantics it enforces

- Backend selection honours `externalTrafficPolicy=Local`
  (external traffic prefers local-node backends, drops if none).
- `internalTrafficPolicy=Local` similarly for cluster-internal.
- Topology-aware routing weights backends by zone/region.
- Unready endpoints excluded; terminating endpoints handled via
  the Kubernetes draining semantics.
- Session affinity populated and refreshed (Service session affinity).
- Maglev LUTs regenerated consistently across nodes (Maglev load balancer).

### Review notes

- A change to Kubernetes Service/Endpoint semantics (new field,
  changed default) needs a matching change in the syncer and,
  usually, in the downstream BPF-map layout. Missing a semantic
  silently diverges from kube-proxy, which is a difficult bug
  class to diagnose.
- A change to the frontend/backend map key or value layout is the
  common case for bumping NAT map versions; see [bpf-overview.md → Cross-cutting review notes](./bpf-overview.md) for the rule.
- A new type of LB filter (future SourceRanges-like features) goes
  here rather than into the TC program — we don't want per-packet
  lookup cost for policy that is stable per-service.
- Syncer changes should preserve the "converge, then apply" model
  — don't emit partial state to BPF mid-update. A partially-synced
  service can serve traffic to a non-existent backend.




## Connect-Time Load Balancer (CTLB)

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
([bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md)) is what lets Felix run without CTLB.

### Limitations

- **Connected UDP.** `connect(2)` on a UDP socket records the chosen
  backend once. If the backend goes away, the socket keeps sending
  to the dead backend. TCP is not affected because each new
  connection runs the CTLB again.
- **Raw sockets bypass CTLB.** Any process using a raw socket builds
  the packet itself and the cgroup hook never fires. Such packets go
  through the regular TC path instead, which means they depend on
  the bpfnat veth to reach a TC program ([bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md)).
- **Per-packet Maglev (Maglev load balancer) does not apply.** CTLB resolves the
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
