# Calico

Calico is a container networking and security platform for Kubernetes. This file fixes the vocabulary the monorepo uses: one canonical word per concept, plus the synonyms to stop reaching for. Architecture belongs in [`DESIGN.md`](DESIGN.md), build and test guidance in [`.claude/CLAUDE.md`](.claude/CLAUDE.md). Neither belongs here.

## Language

A term listed under `_Avoid_` is not a rename order. Existing identifiers keep their names until you are editing that code anyway; the glossary governs new code, new comments, commit messages, and PR descriptions.

### Datastore and API

**Datastore**:
The store of record for Calico configuration and state. A cluster uses exactly one backend: the Kubernetes API server (KDD) or etcdv3.
_Avoid_: backend, database, store

**KDD**:
The Kubernetes datastore driver, which keeps Calico resources in the Kubernetes API. Some are stored as CRDs; others are derived from Kubernetes objects such as Pods and NetworkPolicies rather than stored at all.
_Avoid_: k8s backend, CRD mode

**etcdv3 mode**:
The datastore backend that writes every Calico resource straight to etcd, with no Kubernetes API involved.
_Avoid_: etcd mode, legacy mode

**v3 resource**:
A user-facing Calico API object in `projectcalico.org/v3`, such as GlobalNetworkPolicy or IPPool.
_Avoid_: CRD (that is one way a resource is stored, not what it is)

**Internal API resource**:
A Calico resource in `libcalico-go/lib/apis/internalapi` that is deliberately not part of the public API, such as IPAMBlock or the internal WorkloadEndpoint.
_Avoid_: private resource, hidden CRD

**v1 model**:
The internal key/value representation in `libcalico-go/lib/backend/model` that Felix and confd consume. Not an API version anyone can request.
_Avoid_: backend model, v1 API, legacy model

**Syncer**:
A component that watches the datastore and streams v1-model updates to one consumer. Felix, confd, and Typha each drive one.
_Avoid_: watcher, sync loop

**Update processor**:
The per-resource conversion step inside a syncer that turns a v3 resource into its v1-model equivalent.
_Avoid_: converter, translator

**In-sync**:
The point at which a syncer has delivered its whole initial snapshot. Consumers hold off on mutating kernel state or deleting anything until they see it.
_Avoid_: caught up, ready, synced

**Installation**:
The operator resource declaring the desired Calico install, and the only supported way to configure an operator-managed cluster.
_Avoid_: install CR, the config

### Endpoints and hosts

WEP and HEP are accepted abbreviations in code, in test names, and in the Felix design docs. Spell them out in PR descriptions and release notes, where the reader has no surrounding context.

**Workload endpoint**:
A Calico-managed network interface belonging to a workload, one per pod veth in Kubernetes.
_Avoid_: endpoint (ambiguous on its own), pod interface, veth

**Host endpoint**:
A Calico-managed interface on the host itself, used to apply policy to traffic entering or leaving the host.
_Avoid_: endpoint (ambiguous on its own), node interface

**Node**:
The Calico resource representing one host, carrying its BGP addresses and WireGuard keys. Write "Kubernetes Node" for the Kubernetes object, "host" for the machine, and "calculation node" for a vertex in Felix's calculation graph.
_Avoid_: node, unqualified

**Calculation node**:
One vertex in Felix's calculation graph. Inside `felix/calc` and its design docs, unqualified "node" means this and not a host.
_Avoid_: graph node, calc node

### Policy

**Network policy**:
A Calico policy resource selecting endpoints and carrying ordered ingress and egress rules. NetworkPolicy is namespaced, GlobalNetworkPolicy is cluster-wide.
_Avoid_: ACL, firewall rule, policy where Kubernetes NetworkPolicy could be meant

**Kubernetes network policy**:
The upstream `networking.k8s.io` resource, which Calico enforces alongside its own policies.
_Avoid_: k8s policy, native policy

**Tier**:
An ordered grouping of Calico policies. Tiers evaluate in order, and a rule action can pass evaluation on to the next tier.
_Avoid_: policy group, layer

**Profile**:
A label and rule set attached directly to endpoints, carrying the per-namespace and per-service-account rules Calico derives from Kubernetes.
_Avoid_: default policy, namespace policy

**Rule**:
One match-and-action entry inside a policy or a profile.
_Avoid_: ACL entry, filter

**Selector**:
The Calico label expression deciding which endpoints a policy, rule, or profile applies to. Its syntax is Calico's own, not the Kubernetes one.
_Avoid_: label selector (that is the Kubernetes construct), matcher

**Network set**:
A named set of CIDRs and domain names that rules can select, so addresses outside the cluster can carry labels. NetworkSet is namespaced, GlobalNetworkSet is cluster-wide.
_Avoid_: IP set (that is the dataplane object), CIDR list

**Staged policy**:
A policy evaluated for reporting only and never enforced.
_Avoid_: dry-run policy, preview policy

### IPAM

**IP pool**:
A CIDR that Calico may allocate workload addresses from, together with the encapsulation and routing settings for that CIDR.
_Avoid_: subnet, address pool, CIDR range

**Block**:
A fixed-size CIDR carved out of an IP pool and held by one host at a time. It is the unit of IPAM bookkeeping and of route aggregation.
_Avoid_: chunk, subnet

**Block affinity**:
The claim a host holds on a block, letting it allocate addresses from that block without coordinating with other hosts.
_Avoid_: block ownership, block lease

**Borrowing**:
Allocating an address from a block affine to a different host, which happens when no affine block has room. Strict affinity turns it off.
_Avoid_: cross-node allocation, stealing

**Handle**:
An IPAM identifier grouping the addresses allocated for one thing, so they can all be released together.
_Avoid_: allocation ID, owner

**IP reservation**:
A resource marking addresses inside a pool as never allocatable.
_Avoid_: exclusion, blocklist

**Cooldown**:
The window after an address is released in which Calico will not hand it out again. An address in cooldown is neither allocated nor free, so never count it as either.
_Avoid_: pending release, quarantine

**Leak**:
An IPAM allocation whose workload is gone. A candidate leak has been seen once; a confirmed leak has outlived the grace period.
_Avoid_: orphan, stale allocation, dangling IP

### Dataplane

**Dataplane**:
The kernel-level state Felix maintains on a host to enforce policy and route traffic. Four exist: iptables, nftables, eBPF, and Windows HNS.
_Avoid_: data plane (two words), dataplane backend

**Dataplane driver**:
The Felix-side code owning one dataplane. Name which one; "the dataplane" on its own means the kernel state, not the code that writes it.
_Avoid_: dataplane implementation, dataplane backend

**Calculation graph**:
Felix's policy resolution engine in `felix/calc`, which turns datastore updates into the per-endpoint policy a dataplane driver programs.
_Avoid_: the brain, policy engine, resolver

**IP set**:
A dataplane object holding the addresses currently matching one selector. Rules reference the set, so a rule does not change as membership does.
_Avoid_: ipset (the Linux tool, fine in commands), address group

**Resync**:
The full reconciliation Felix runs against the dataplane when its cached view of that dataplane may be stale.
_Avoid_: refresh, full sync

**`*tables`**:
Either Linux dataplane that renders rules rather than BPF programs, meaning iptables or nftables. The project's term of art for "the non-BPF Linux dataplane".
_Avoid_: legacy dataplane, netfilter dataplane

**Untracked policy**:
Policy evaluated without connection tracking, in the raw table or in XDP.
_Avoid_: stateless policy, pre-DNAT policy (that is a separate thing)

**Failsafe port**:
A port Felix always allows, so that fixing a broken cluster stays possible. The polarity is the opposite of "fail closed".
_Avoid_: failsafe, unqualified

**DSR**:
Direct server return, where a service's reply goes straight from the backend to the client instead of back through the node that load-balanced it.
_Avoid_: direct return

**CTLB**:
The connect-time load balancer, which rewrites the destination at `connect()` in a cgroup BPF program rather than per packet.
_Avoid_: socket LB, ctlb

**Flow log**:
A record of one aggregated traffic flow between endpoints, emitted by Felix and aggregated by Goldmane.
_Avoid_: connection log, flow record

### Routing and encapsulation

**Overlay**:
A pool configured so workload traffic crossing hosts is encapsulated.
_Avoid_: tunnel mode, encap mode

**IPIP**:
The IP-in-IP encapsulation available to a pool.
_Avoid_: IP-in-IP, ipip tunnel

**VXLAN**:
The UDP encapsulation available to a pool, and the option that works where the network drops IPIP.
_Avoid_: vxlan tunnel

**WireGuard**:
The encryption Calico can apply to host-to-host workload traffic, chosen independently of the pool's encapsulation.
_Avoid_: wireguard tunnel, encrypted overlay

**BGP**:
The routing protocol Calico uses to distribute workload routes between hosts, spoken by BIRD and configured by confd.
_Avoid_: peering protocol

**Node-to-node mesh**:
The default BGP topology, where every node peers with every other node.
_Avoid_: full mesh

**Route reflector**:
A node or external router that other nodes peer with instead of running a node-to-node mesh.
_Avoid_: hub

**Cluster route**:
The route one node needs in order to reach a workload running on a different node.
_Avoid_: remote route, block route, pod route

**VTEP**:
A VXLAN tunnel endpoint: the per-node address and MAC that VXLAN traffic is encapsulated to.
_Avoid_: tunnel endpoint (ambiguous), vtep

### Components

**Felix**:
The per-host agent that resolves policy and programs the dataplane.
_Avoid_: the agent

**Typha**:
The fan-out proxy sitting between the datastore and the Felix instances, so datastore watch load does not scale with node count.
_Avoid_: the proxy, cache

**confd**:
The per-host daemon that renders BIRD configuration from datastore updates.
_Avoid_: config daemon

**BIRD**:
The BGP daemon in the node image that distributes and installs routes.
_Avoid_: the router

**calico-node**:
The per-host pod and image running Felix, confd, and BIRD under runit, plus the node startup sequence.
_Avoid_: node agent, the node (that is the Calico resource or the machine)

**Operator**:
The tigera-operator deployment that installs and reconciles Calico from an Installation resource.
_Avoid_: the installer

**kube-controllers**:
The cluster-wide controllers that mirror Kubernetes objects into Calico resources and garbage-collect Calico state.
_Avoid_: the controllers

**CNI plugin**:
The binary kubelet invokes to attach a pod to the Calico network and allocate its address.
_Avoid_: the CNI

**apiserver**:
The aggregated Kubernetes API server that serves `projectcalico.org/v3`.
_Avoid_: the aggregator

**calicoctl**:
The CLI for reading and writing Calico resources.

**Goldmane**:
The cluster-wide flow log aggregator.
_Avoid_: the aggregator

**Whisker**:
The flow log UI, served by whisker-backend.
_Avoid_: the UI, the dashboard

**Guardian**:
The tunnel proxy connecting a cluster to a management cluster.
_Avoid_: the tunnel

**Dikastes**:
The per-pod sidecar enforcing application-layer policy, built from `app-policy/`.
_Avoid_: the sidecar, L7 proxy

**pod2daemon**:
The volume driver that mounts the credentials socket Dikastes needs into pods.

## Words that need a qualifier

Each of these carries several unrelated meanings across the repo, so the bare word tells a reader nothing. Say which one you mean.

| Word | Meanings in play | Write instead |
|---|---|---|
| backend | a service's backend pod, the netfilter backend, the datastore backend, whisker-backend | backend pod, netfilter backend, datastore backend |
| dataplane | the kernel state, the driver code, the selected mode, the calc-graph contract | kernel state, dataplane driver, dataplane mode, dataplane API |
| driver | the selector in `dataplane/driver.go`, the reconciling layer under Felix's managers, a `*tables` package, KDD, a volume driver | name which |
| manager | Felix's `Manager` interface, the operator status manager, controller-runtime's Manager, the Enterprise `Manager` CRD | name which |
| syncer | the datastore stream, Felix's route syncers, the BPF service syncer, kube-controllers' block syncer | datastore syncer, route syncer, service syncer, block syncer |
| endpoint | a workload endpoint, a host endpoint, Kubernetes `Endpoints`, an HTTP endpoint, a VTEP | workload endpoint, host endpoint, Kubernetes Endpoints, HTTP endpoint, VTEP |
| node | the Calico Node, a Kubernetes Node, the machine, a calculation node | Node, Kubernetes Node, host, calculation node |
| block | an IPAM block, a run of BPF backend-map slots, a mark-bit range, the verb meaning back-pressure | IPAM block, backend-map range, mark-bit range |
| policy | a Calico policy resource, the BPF policy program, policy direction, `OwnershipPolicy`, `clusterRoutePolicy`, Kubernetes traffic policy, policy-based routing | name which |
| rule | `model.Rule`, an iptables or nftables rule, an ip rule, a BGPFilter rule, a BIRD filter statement | Calico rule, `*tables` rule, ip rule, BGP filter rule, BIRD filter |
| table | a netfilter table, Calico's nft table, `generictables.Table` (a chain set), a route table, the BPF conntrack table, the Maglev LUT, BIRD's table | name which |
| map | a BPF map, the jump map (programs, not data), an nftables match-action map, an in-memory Go map | BPF map, jump map, nft map, Go map |
| flow | a 5-tuple connection, a Goldmane aggregated flow, an nftables flowtable entry, flow-based VXLAN mode, control flow | connection, aggregated flow, flowtable entry, flow-based mode |
| flow log | BPF ring-buffer events, NFLOG-derived logs from `felix/collector/`, the Goldmane and Whisker feature | name the producer |
| affinity | a block affinity, `sessionAffinity`, UDP backend re-selection, the `virtual:load-balancer` affinity string | block affinity, session affinity |
| claim | an IPAM block claim, a Goldmane emission claim, an idempotence latch, OwnerReference ownership, route ownership | name which |
| confirmed | a confirmed block affinity, a confirmed leak, a conntrack-confirmed flow | name which |
| pending | a pending block affinity, the `EventSequencer`'s pending buffers, a manager's unflushed state | name which |
| local | hosted on this node, `externalTrafficPolicy=Local`, `addrtype=LOCAL`, host-local IPAM, link-local | local to this node, Local traffic policy, host-addressed, host-local IPAM, link-local |
| mark | an skb mark, a connmark, a mark-bit allocation, mark-and-sweep, the IPAM GC's state transitions | skb mark, connmark, mark bits |
| reserved | an IPReservation carve-out, the utilization column, the skb-mark range, built-in IP-set IDs, the Windows reserved handle, VNI `0xca11c0` | name which |
| render | operator manifest generation, confd template rendering, Felix `*tables` rule rendering | name which |
| operator | a person running Calico, the tigera-operator deployment | an administrator, the operator |
| component | a top-level directory, a `calico component <name>` subcommand, an operator-deployed CRD and controller, a versioned image in `pkg/components`, an object inside Felix | name which |
| GC | the IPAM library's cooldown deallocation, the kube-controllers IPAM GC, kernel orphan cleanup | name which; "the IPAM GC" is the proper name for the kube-controllers one |
| release | releasing an IP, a product release, BIRD withdrawing a route, releasing a latch | name which |
| fast path | the BPF per-packet path, the fast program build, the nftables flowtable offload, latency-sensitive Go | name which |
| FV | Felix's calc-graph FV (unit tests despite the name), Felix FV, Goldmane FV, operator FV against kind | name the suite |
| variant | Calico or Enterprise, a compiled BPF program variant, a `_notrace` or `_DEBUG` build | name which |
