# Felix glossary

This file extends the [root glossary](../GLOSSARY.md). It covers Felix's calculation graph and daemon, its Linux dataplane (iptables and nftables modes), and its BPF dataplane. Terms already defined in the root file are not repeated here unless Felix narrows them.

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Config-change restart](../GLOSSARY.md#config-change-restart)
- [Datastore syncer](../GLOSSARY.md#datastore-syncer)
- [Elevated route](../GLOSSARY.md#elevated-route)
- [Endpoint status directory](../GLOSSARY.md#endpoint-status-directory)
- [Pass-through kind](../GLOSSARY.md#pass-through-kind)
- [Policy Sync API](../GLOSSARY.md#policy-sync-api)
- [Syncer output](../GLOSSARY.md#syncer-output)

## Calc graph

The calculation graph turns the datastore's contents into the desired state of one host. The daemon starts it and feeds it, and the dataplane driver consumes what it emits.

### Building blocks

Felix process, top layer:

| Building block | Code | Responsible for |
|---|---|---|
| Daemon | `felix/daemon/daemon.go` (`Run`) | Sequencing startup (config load, dataplane driver start, syncer, calc graph, metrics), then waiting in the shutdown monitor. |
| Config | `felix/config/config_params.go` (`Config`) | Parsed, validated parameters merged from every config source. |
| Datastore syncer | `felix/daemon/daemon.go` (`Run`) | Streaming v1-model updates and sync status into Felix, either directly (`felixsyncer`) or through Typha (`syncclient`). |
| Dedupe buffer | `felix/daemon/daemon.go` (`Run`) | Coalescing syncer updates between the syncer goroutine and the validation filter. |
| Validation filter | `felix/calc/validation_filter.go` (`ValidationFilter`) | Validating each update and replacing an invalid value with `nil` before the graph sees it. |
| Async calc graph | `felix/calc/async_calc_graph.go` (`AsyncCalcGraph`) | Running the calc graph on its own goroutine, throttling flushes, emitting in-sync, and reporting health. |
| Calculation graph | `felix/calc/calc_graph.go` (`NewCalculationGraph`) | Turning datastore state into this host's desired dataplane state. |
| Event sequencer | `felix/calc/event_sequencer.go` (`EventSequencer`) | Buffering, coalescing and flushing the graph's output in dependency order. |
| Dataplane connector | `felix/daemon/daemon.go` (`DataplaneConnector`) | Forwarding calc-graph output to the dataplane driver and status back, and triggering a config-change restart when needed. |
| Dataplane driver | `felix/dataplane/driver_defs.go` (`DataplaneDriver`) | The send and receive endpoint the connector talks to, in-process or external. |
| Policy sync server | `felix/policysync/server.go` (`Server`) | Serving per-workload policy to Dikastes over the Policy Sync API. |
| Lookups cache | `felix/calc/lookups_cache.go` (`LookupsCache`) | Endpoint, policy, network set and service lookups for the flow log collector, built only when flow logs are enabled. |
| Stats collector | `felix/calc/stats_collector.go` (`StatsCollector`) | Counting cluster objects for the `felix_cluster_*` metrics and usage reporting. |
| Shutdown monitor | `felix/daemon/daemon.go` (`monitorAndManageShutdown`) | Waiting for a failure reason, shutting down the driver, and exiting with the config-change restart code when appropriate. |

Inside the calculation graph:

| Building block | Code | Responsible for |
|---|---|---|
| All-update dispatcher | `felix/calc/calc_graph.go` (`NewCalculationGraph`) | The entry node, which fans each update out by key type. |
| Local endpoint dispatcher | `felix/calc/calc_graph.go` (`endpointHostnameFilter`) | Carrying only endpoints hosted on this node. |
| Remote endpoint dispatcher | `felix/calc/calc_graph.go` (`remoteEndpointFilter`) | Carrying only endpoints on other nodes, for the lookups cache. |
| Active rules calculator | `felix/calc/active_rules_calculator.go` (`ActiveRulesCalculator`) | Matching local endpoints against policy and profile selectors, and reporting which policies and profiles are active and which match which endpoint. |
| Rule scanner | `felix/calc/rule_scanner.go` (`RuleScanner`) | Converting active rules into parsed rules and tracking which IP sets (selectors, named ports, services) are active. |
| Policy resolver | `felix/calc/policy_resolver.go` (`PolicyResolver`) | Producing each local endpoint's ordered tier and policy list, using the policy sorter. |
| IP set member index | `felix/labelindex/named_port_index.go` (`SelectorAndNamedPortIndex`) | Computing the members of every active selector and named-port IP set across endpoints and network sets. |
| Service index | `felix/serviceindex/serviceindex.go` (`ServiceIndex`) | Computing the members of service-based IP sets from EndpointSlices. |
| Live migration calculator | `felix/calc/live_migration_calculator.go` (`LiveMigrationCalculator`) | Setting the live migration role on local workload endpoints. |
| Istio calculator | `felix/calc/istio_calculator.go` (`IstioCalculator`) | Marking local workload endpoints that are in the Istio ambient mesh. |
| Active BGP peer calculator | `felix/calc/active_bpgpeer_calculator.go` (`ActiveBGPPeerCalculator`) | Choosing which local workload endpoint gets a local BGP peer. |
| L3 route resolver | `felix/calc/l3_route_resolver.go` (`L3RouteResolver`) | Building longest-prefix routes from IPAM blocks, IP pools, node addresses, workload endpoints and tunnel addresses. |
| VXLAN resolver | `felix/calc/vxlan_resolver.go` (`VXLANResolver`) | Computing one VTEP per host when VXLAN is in use. |
| Encapsulation resolver | `felix/calc/encapsulation_resolver.go` (`EncapsulationResolver`) | Deriving IPIP, VXLAN and no-encap state from IP pools. |
| Dataplane pass-through | `felix/calc/dataplane_passthru.go` (`DataplanePassthru`) | Forwarding host metadata, IP pools, WireGuard, BGP config and services with little transformation. |
| Profile decoder | `felix/calc/profile_decoder.go` (`ProfileDecoder`) | Decoding namespace and service-account profiles into their own update messages. |
| Config batcher | `felix/calc/config_batcher.go` (`ConfigBatcher`) | Collecting global, selector-scoped and per-host FelixConfiguration plus the ready flag, and emitting one batch after in-sync. |
| Label inheritance index | `felix/labelindex/label_inheritance_index.go` (`InheritIndex`) | Matching selectors to endpoints with profile label inheritance, for the active rules calculator and the BGP peer calculator. |
| Overlap suppressor | `felix/labelindex/named_port_index.go` (`OverlapSuppressor`) | Dropping CIDR members masked by a wider member of the same IP set. |

### Terms

**Calculation graph**:
Felix's policy resolution engine: a single-threaded directed graph of calculation nodes that converts datastore updates into this host's desired dataplane state. Also written "calc graph".
Code: `felix/calc/calc_graph.go` (`NewCalculationGraph`).
_Avoid_: calculation engine, processing graph, the brain

**Calculation node**:
One vertex of the calculation graph, connected to the others by direct function calls. Inside `felix/calc`, unqualified "node" means this.
Code: `felix/design/calc-graph.md`.
_Avoid_: graph node, calc node

**Async calc graph**:
The wrapper that owns the calculation graph's goroutine, input channel, flush throttle and output channels. It is not the graph itself.
Code: `felix/calc/async_calc_graph.go` (`AsyncCalcGraph`).
_Avoid_: calc graph, where the goroutine wrapper is meant

**Calc-graph input pipeline**:
The chain that carries updates into the graph: datastore syncer, dedupe buffer, validation filter, then the async calc graph's input channel.
Code: `felix/daemon/daemon.go` (`Run`).
_Avoid_: ingest pipeline, syncer pipeline (that is Typha's)

**Calc-graph consumers**:
The three receivers of calc-graph output: the dataplane connector, the policy sync server and the flow log collector. The dataplane driver is only one of them.
Code: `felix/daemon/daemon.go` (`calcGraphClientChannels`).
_Avoid_: dataplane, where all three are meant

**Dispatcher**:
A fan-out that calls the handlers registered for an update's key type.
Code: `felix/dispatcher/dispatcher.go` (`Dispatcher`).
_Avoid_: router

**filterOut**:
A handler's return flag that hides an update from later handlers in the same dispatcher list.
Code: `felix/dispatcher/dispatcher.go` (`UpdateHandler`).
_Avoid_: filter (it means several things)

**Local endpoint**:
A workload or host endpoint whose key hostname equals Felix's own hostname.
Code: `felix/calc/calc_graph.go` (`endpointHostnameFilter`).
_Avoid_: local, unqualified

**Active policy**:
A policy that selects at least one local endpoint, or that carries the assume-needed-on-every-node performance hint. An active profile is the same test for a profile.
Code: `felix/calc/active_rules_calculator.go` (`ActiveRulesCalculator`).
_Avoid_: enabled policy

**Active IP set**:
An IP set referenced by at least one rule of an active policy or profile.
Code: `felix/calc/calc_graph.go` (`NewCalculationGraph`).
_Avoid_: active selector

**Policy match**:
The active rules calculator's event that one policy's selector matches one local endpoint.
Code: `felix/calc/active_rules_calculator.go` (`PolicyMatchListener`).
_Avoid_: bare match (a selector can match many kinds of thing)

**Parsed rule**:
A policy's or profile's rule with its selectors and named ports replaced by IP set IDs.
Code: `felix/calc/rule_scanner.go` (`ParsedRule`).
_Avoid_: compiled rule

**IP set data**:
The calc graph's description of one IP set: a selector, optionally with a named port, or a service.
Code: `felix/calc/rule_scanner.go` (`IPSetData`).
_Avoid_: ipset (that is the kernel's set, not the calc graph's description of one)

**IP set member index**:
The calculation node that computes the members of every active selector and named-port IP set, treating network sets as endpoints. Its type is `SelectorAndNamedPortIndex`.
Code: `felix/labelindex/named_port_index.go` (`SelectorAndNamedPortIndex`).
_Avoid_: named port index, label inheritance index (that is a different node that serves the active rules calculator)

**IP set member**:
One entry of a calc-graph IP set: an IP, a CIDR, or an IP, port and protocol triple.
Code: `felix/labelindex/ipsetmember/ip_set_member.go` (`IPSetMember`).
_Avoid_: contribution

**Overlap suppression**:
Dropping an IP set's CIDR member when a wider member of the same set already covers it.
Code: `felix/labelindex/named_port_index.go` (`OverlapSuppressor`).
_Avoid_: dedup (that means counting several contributors to one member)

**Label parent**:
A profile whose labels an endpoint inherits in the label indexes.
Code: `felix/labelindex/label_inheritance_index.go` (`InheritIndex`).
_Avoid_: parent, unqualified

**Endpoint computed data**:
Per-workload-endpoint data computed by calculation nodes and applied onto the outgoing workload endpoint message, rather than stored on the resource.
Code: `felix/calc/event_sequencer.go` (`EndpointComputedData`).
_Avoid_: nothing known

**Tier info**:
One tier's ordered ingress and egress policy IDs for one endpoint.
Code: `felix/calc/policy_sorter.go` (`TierInfo`).
_Avoid_: filteredTiers

**Pending buffer**:
An event sequencer map or set holding the latest unflushed change for each object.
Code: `felix/calc/event_sequencer.go` (`EventSequencer`).
_Avoid_: queue (it is not first-in first-out)

**Graph flush**:
The first step of a flush, in which the graph's calculation nodes release deferred work.
Code: `felix/calc/calc_graph.go` (`CalcGraph`).
_Avoid_: apply (that is the dataplane's cycle)

**Sequencer flush**:
The second step of a flush, in which the event sequencer emits its pending buffers.
Code: `felix/calc/event_sequencer.go` (`EventSequencer`).
_Avoid_: apply

**Ready flag**:
The datastore's `ReadyFlagKey`.
Code: `felix/calc/config_batcher.go` (`ConfigBatcher`).
_Avoid_: readiness (that is health)

**Config source**:
Where a parameter value came from: environment variable, config file, or one of the three FelixConfiguration sources (global, selector-scoped, per-host).
Code: `felix/config/config_params.go` (`Source`).
_Avoid_: priority

**Local-only parameter**:
A parameter tagged `local`, which cannot be set from the datastore.
Code: `felix/config/config_params.go` (`Source`).
_Avoid_: local source, bare local (it means several things)

**Selector-scoped FelixConfiguration**:
A FelixConfiguration that is neither `default` nor `node.<name>` and applies to the nodes its node selector matches.
Code: `felix/calc/config_batcher.go` (`ConfigBatcher`) and `felix/config/config_params.go` (`DatastorePerSelector`).
_Avoid_: per-node-selector config

**Dataplane connector**:
The daemon object that forwards calc-graph output to the dataplane driver and passes status back from it.
Code: `felix/daemon/daemon.go` (`DataplaneConnector`).
_Avoid_: glue logic, dataplane driver (that is the other end of the connector)

**Calc-graph FV**:
A unit test, despite the name, that drives the assembled graph from datastore states to emitted messages.
Code: `felix/calc/calc_graph_fv_test.go`.
_Avoid_: FV, unqualified

## Linux dataplane

The Linux dataplane is the in-process driver that programs the kernel in iptables and nftables modes (and hosts BPF mode's shared loop). It has two layers: managers decide what the kernel should contain, and reconciling drivers make the kernel match.

### Building blocks

Dataplane driver layer:

| Building block | Code | Responsible for |
|---|---|---|
| Dataplane driver interface | `felix/dataplane/driver_defs.go` (`DataplaneDriver`) | The send and receive seam between the calc-graph side and whichever dataplane runs. |
| Driver selector | `felix/dataplane/driver.go` (`StartDataplaneDriver`) | Picking the inactive, internal Linux or external-process driver, and allocating mark bits. |
| Internal dataplane | `felix/dataplane/linux/int_dataplane.go` (`InternalDataplane`) | The in-process Linux driver: main loop, manager registry and `apply()`, for iptables, nftables and BPF modes. |
| Inactive dataplane | `felix/dataplane/inactive/inactive_dataplane.go` (`InactiveDataplane`) | A no-op driver used when this Felix is not the leader. |
| External dataplane driver | `felix/dataplane/external/ext_dataplane.go` (`StartExtDataplaneDriver`) | Running a driver binary as a child process and piping protobuf to it. |
| Main loop | `felix/dataplane/linux/int_dataplane.go` (`loopUpdatingDataplane`) | Receiving messages, timers and interface events, and admitting `apply()` through the throttle. |
| Apply | `felix/dataplane/linux/int_dataplane.go` (`apply`) | One ordered reconcile cycle across every manager and reconciling driver. |
| Interface monitor | `felix/ifacemonitor/iface_monitor.go` (`InterfaceMonitor`) | Reporting netlink link and address events, plus its own in-sync signal. |

Managers and reconciling drivers:

| Building block | Code | Responsible for |
|---|---|---|
| Manager interface | `felix/dataplane/linux/int_dataplane.go` (`Manager`) | `OnUpdate` (record the change, no kernel I/O) and `CompleteDeferredWork` (program the kernel). |
| Endpoint manager | `felix/dataplane/linux/endpoint_mgr.go` (`endpointManager`) | Per-endpoint chains, dispatch chains, workload routes, interface sysctls, host endpoint resolution and endpoint status. |
| Policy manager | `felix/dataplane/linux/policy_mgr.go` (`policyManager`) | Rendering policies and profiles into chains. |
| IP sets manager | `felix/dataplane/ipsets/ipsets_mgr.go` (`IPSetsManager`) | Passing calc-graph IP set updates to the IP set driver. |
| VXLAN manager | `felix/dataplane/linux/vxlan_mgr.go` (`vxlanManager`) | The VXLAN device, VTEP forwarding and ARP entries, and VXLAN routes. |
| IPIP manager | `felix/dataplane/linux/ipip_mgr.go` (`ipipManager`) | The `tunl0` device, and IPIP routes when Felix rather than BIRD owns them. |
| No-encap manager | `felix/dataplane/linux/noencap_mgr.go` (`noEncapManager`) | Direct, unencapsulated cluster routes. |
| Route manager | `felix/dataplane/linux/route_mgr.go` (`routeManager`) | The tunnel, same-subnet and blackhole route computation shared by the three managers above. It is a helper, not a registered manager. |
| WireGuard manager | `felix/dataplane/linux/wireguard_mgr.go` (`wireguardManager`) | Wrapping the WireGuard driver and exposing it as a route syncer. |
| Masquerade manager | `felix/dataplane/linux/masq_mgr.go` (`masqManager`) | NAT outgoing: the pool IP sets and the masquerade rule. |
| Live migration monitor | `felix/dataplane/linux/live_migration.go` (`liveMigrationMonitor`) | One per-workload state machine feeding both IP families' endpoint managers. |
| Endpoint status combiner | `felix/dataplane/linux/status_combiner.go` (`endpointStatusCombiner`) | Merging IPv4 and IPv6 endpoint status and reporting the worse of the two. |
| Proxy neighbor manager | `felix/dataplane/linux/proxy_neigh_mgr.go` (`proxyNeighManager`) | A userspace ARP and NDP responder on host NICs for no-encap pod and LoadBalancer addresses. |
| Flowtable manager | `felix/dataplane/linux/flowtable_mgr.go` (`flowtableManager`) | The nftables flowtable's device set. |
| Table interface | `felix/generictables/table.go` (`Table`) | The backend-neutral chain and rule API that managers write to. |
| iptables table | `felix/iptables/table.go` (`Table`) | One netfilter table: hash read-back and `iptables-restore`. |
| nftables root table | `felix/nftables/table.go` (`NftablesTable`) | The single `calico` nft table per family, with its sets and maps. |
| Rule renderer | `felix/rules/rule_defs.go` (`RuleRenderer`) | Converting policy, endpoints and static config into `*tables` chains. |
| IP sets driver | `felix/ipsets/ipsets.go` (`IPSets`) | One IP family of kernel ipsets, through the `ipset` command. |
| nftables IP sets driver | `felix/nftables/ipsets.go` (`IPSets`) | IP sets as nft sets inside the root table. |
| Route table | `felix/routetable/route_table.go` (`RouteTable`) | One kernel routing table: class-based conflict resolution, ownership, grace period, conntrack cleanup. |
| Route rules | `felix/routerule/route_rule.go` (`RouteRules`) | One IP family's policy-routing rules (`ip rule`). |
| VXLAN FDB | `felix/vxlanfdb/vxlan_fdb.go` (`VXLANFDB`) | Static forwarding and ARP or NDP entries for the VXLAN device. |
| WireGuard driver | `felix/wireguard/wireguard.go` (`Wireguard`) | The WireGuard device, peers, routing table and `ip rule`. |

### Terms

**Dataplane driver**:
The Felix building block behind the `DataplaneDriver` send and receive interface, which is the process boundary between the calc graph side and whichever dataplane runs. It is in-process (`InternalDataplane`, which runs the iptables, nftables and BPF modes) or an external process.
Code: `felix/dataplane/driver_defs.go` (`DataplaneDriver`), `felix/dataplane/linux/int_dataplane.go` (`InternalDataplane`).
_Avoid_: dataplane implementation, dataplane backend, bare "driver"

**Internal dataplane**:
The in-process Linux dataplane driver that hosts the managers, reconciling drivers and main loop for iptables, nftables and BPF modes.
Code: `felix/dataplane/linux/int_dataplane.go` (`InternalDataplane`).
_Avoid_: iptables driver

**Manager**:
An object implementing `Manager` that turns calc-graph messages into desired kernel state for one feature. Reserve the word for these objects.
Code: `felix/dataplane/linux/int_dataplane.go` (`Manager`).
_Avoid_: driver, for a manager

**Reconciling driver**:
A package that owns one kind of kernel object (IP sets, a `*tables` table, a routing table, ip rules, the VXLAN FDB, WireGuard) and drives it to the desired state. It is the lower layer, beneath the managers.
Code: `felix/ipsets/ipsets.go` (`IPSets`), `felix/routetable/route_table.go` (`RouteTable`), `felix/DESIGN.md`.
_Avoid_: dataplane layer, manager (for a reconciling driver), bare "driver"

**Apply**:
One ordered, throttled reconcile cycle of every manager and reconciling driver.
Code: `felix/dataplane/linux/int_dataplane.go` (`apply`).
_Avoid_: resync (a narrower action)

**Needs-sync flag**:
The flag meaning an `apply()` is owed.
Code: `felix/dataplane/linux/int_dataplane.go` (`dataplaneNeedsSync`).
_Avoid_: dirty

**OnUpdate and CompleteDeferredWork**:
The two `Manager` phases. `OnUpdate` records the change and marks state dirty without kernel I/O. `CompleteDeferredWork` programs the kernel.
Code: `felix/dataplane/linux/int_dataplane.go` (`Manager`).
_Avoid_: sync, flush

**Resolution pass**:
The loop that calls `ResolveUpdateBatch` on every manager that implements it.
Code: `felix/dataplane/linux/int_dataplane.go` (`UpdateBatchResolver`).
_Avoid_: resolve update batch, resync (that is a different thing)

**In-sync gate**:
The condition that admits the first `apply()`: the datastore is in-sync and the interface monitor has reported every existing interface.
Code: `felix/dataplane/linux/int_dataplane.go` (`ifaceMonitorInSync`).
_Avoid_: apply gate

**Dataplane in-sync**:
The message the dataplane sends back to the calc graph side after its first clean `apply()`. Always say "datastore in-sync" or "dataplane in-sync".
Code: `felix/proto/felixbackend.proto` (`DataplaneInSync`).
_Avoid_: bare in-sync (say datastore in-sync or dataplane in-sync)

**Refresh timer**:
A periodic timer that queues a resync on a set of reconciling drivers (routes or IP sets).
Code: `felix/dataplane/linux/int_dataplane.go` (`forceRouteRefresh`).
_Avoid_: refresh, for the repair action

**Resync (dataplane)**:
A reconciling driver's read-back of kernel state to repair drift. Say "datastore resync" for the syncer's snapshot phase.
Code: `felix/routetable/interface.go` (`QueueResync`).
_Avoid_: full sync

**Must and background resync**:
The two priorities in the IP sets driver's incremental resync queue.
Code: `felix/ipsets/resync_queue.go` (`ResyncQueue`).
_Avoid_: bare resync (it means several things)

**Logical table**:
A netfilter table name (filter, nat, mangle or raw) as managers see it through the `Table` interface. In nftables mode all logical tables live in the root table.
Code: `felix/nftables/table_layer.go` (`tableLayer`).
_Avoid_: table, unqualified

**Root table**:
The single nftables table per IP family (`calico`, or `calico-arp`) that holds every logical table's chains, sets and maps.
Code: `felix/nftables/table.go` (`NftablesTable`).
_Avoid_: NftablesTable, table on its own (a logical table is not the root table)

**Shared tables**:
The kernel tables filter, nat, mangle and raw, which Calico shares with other software, with one copy for each iptables backend.
Code: `felix/rules/rulesdefs/rulesdefs.go` (`RuleHashPrefix`).
_Avoid_: legacy copies, nftables copies, legacy (reserved for the iptables-legacy backend)

**Rule insertion and full chain update**:
The two `Table` write modes: hook a Felix rule into a kernel-owned chain, or replace the contents of a Felix-owned chain.
Code: `felix/iptables/table.go` (`InsertOrAppendRules`).
_Avoid_: nothing known

**Rule hash**:
A deterministic hash of a rendered rule, stored in the rule's comment after the `cali:` prefix.
Code: `felix/generictables/rules.go` (`Rule`) and `felix/rules/rulesdefs/rulesdefs.go` (`RuleHashPrefix`).
_Avoid_: rule ID, hash comment

**Dispatch chain**:
A chain tree that sends a packet to its endpoint's per-endpoint chain by interface name.
Code: `felix/rules/dispatch.go` (`DispatchChains`).
_Avoid_: dispatch map

**Per-endpoint chain**:
One of the `cali-tw-`, `cali-fw-`, `cali-th-` or `cali-fh-` chains, holding the policy jumps for one endpoint and direction.
Code: `felix/rules/rule_defs.go` (`WorkloadToEndpointPfx`).
_Avoid_: dispatch chain (that routes to these chains, and is a different thing)

**Policy group**:
A run of consecutive policies in one tier and direction, programmed as a shared `cali-gi-` or `cali-go-` chain.
Code: `felix/rules/endpoints.go` (`TierPolicyGroups`).
_Avoid_: policy set

**Static chains**:
Chains rendered from config alone, not from any endpoint or policy, such as `cali-INPUT` and `cali-FORWARD`.
Code: `felix/rules/rule_defs.go` (`StaticFilterTableChains`).
_Avoid_: top-level static chains

**Endpoint mark**:
A per-endpoint value kept in the `*tables` mark bits.
Code: `felix/rules/epmark.go` (`DefaultEPMarkManager`).
_Avoid_: EndpointMarkMapper, bare mark (it means several things)

**Mark bits**:
The packet mark bits that Felix allocates to its `*tables` features.
Code: `felix/dataplane/driver.go` (`StartDataplaneDriver`) and `felix/markbits/mark_bits.go` (`MarkBitsManager`).
_Avoid_: bare mark (it means several things), skb mark (that is the whole mark field)

**Route class**:
The producer category of a desired route (local workload, VXLAN, IPIP, no-encap, WireGuard, blackhole).
Code: `felix/routetable/defs.go` (`RouteClass`).
_Avoid_: ownership, for a route class

**Route key**:
The kernel route-table key a route is indexed by: CIDR, TOS and priority.
Code: `felix/routetable/defs.go` (`RouteKey`).
_Avoid_: bare CIDR (a route key also has TOS and priority)

**Route target**:
The desired route for one route key: type, gateway, source, MAC, protocol, multipath and MTU.
Code: `felix/routetable/defs.go` (`Target`).
_Avoid_: route (that is the kernel's entry, and the target is the desired one)

**InterfaceNone**:
The pseudo-interface name for routes with no outbound interface, such as blackhole, throw and unreachable routes.
Code: `felix/routetable/defs.go` (`InterfaceNone`).
_Avoid_: nothing known

**Ownership policy**:
The route table's classifier that decides whether a kernel route or interface belongs to Felix.
Code: `felix/routetable/route_table.go` (`OwnershipPolicy`).
_Avoid_: RouteClass (that is the producer key, a different thing), bare ownership (it means several things)

**Route cleanup grace period**:
The delay before Felix deletes an owned route on an interface it has no endpoint for.
Code: `felix/routetable/route_table.go` (`graceInfo`).
_Avoid_: graceInfo

**Route syncer**:
Anything implementing `SyncerInterface`: the route tables and the WireGuard driver.
Code: `felix/routetable/interface.go` (`SyncerInterface`).
_Avoid_: syncer, unqualified

**Class view**:
A route table wrapper pinned to one route class and handed to a single producer.
Code: `felix/routetable/interface.go` (`ClassView`).
_Avoid_: route table (that is the whole table, not one class's view)

**Calico route proto**:
The netlink route protocol number 80, which Felix stamps on routes with no Calico interface: blackhole, same-subnet and tunnel routes.
Code: `felix/dataplane/linux/dataplanedefs/dataplane_defs.go` (`DefaultRouteProto`).
_Avoid_: DeviceRouteProtocol (a separate setting that applies to routes on Calico interfaces)

**IP set ID and IP set name**:
The ID is the calc graph's identifier for a set. The name is the truncated, prefixed kernel name derived from it, such as `cali40...`.
Code: `felix/ipsets/ipset_defs.go` (`IPSetMetadata`).
_Avoid_: bare name (the ID and the kernel name differ)

**Main IP set and temp IP set**:
The set under its real kernel name, and its temporary copy.
Code: `felix/ipsets/ipset_defs.go` (`IPSetMetadata`).
_Avoid_: nothing known

**Host endpoint resolution**:
Mapping each host endpoint to the interfaces it covers, either by interface name or by the expected IP addresses.
Code: `felix/dataplane/linux/endpoint_mgr.go` (`endpointManager`).
_Avoid_: nothing known

**`shadowedWlEndpoints`**:
A local workload endpoint that Felix ignores because another endpoint claims the same interface name.
Code: `felix/dataplane/linux/endpoint_mgr.go` (`endpointManager`).
_Avoid_: nothing known

**`liveMigrationFSM`**:
The per-workload state machine with the states base, target, live and time-wait.
Code: `felix/dataplane/linux/live_migration.go` (`liveMigrationFSM`).
_Avoid_: liveMigrationMonitor

**Proxy neighbor manager**:
The manager that answers ARP and NDP for no-encap pod and LoadBalancer addresses on host NICs from userspace. Abbreviated PNM.
Code: `felix/dataplane/linux/proxy_neigh_mgr.go` (`proxyNeighManager`).
_Avoid_: proxy ARP (that is the kernel sysctl)

**iptables-mode XDP**:
XDP-based untracked-policy acceleration layered on iptables mode. It is a separate implementation from the XDP program in the BPF dataplane.
Code: `felix/dataplane/linux/xdp_state.go` (`xdpState`).
_Avoid_: XDP, unqualified

**Flowtable offload**:
In nftables mode, handing established flows to the kernel's flowtable so they skip most of the rule chain.
Code: `felix/dataplane/linux/flowtable_mgr.go` (`flowtableManager`).
_Avoid_: fast path, for this

**Cleanup-only table**:
A `Table` built only to remove another backend's or kube-proxy's leftover state, never to program rules.
Code: `felix/generictables/table.go` (`CleanupTable`).
_Avoid_: CleanupOnly

**Foreign-table sweep**:
The removal of Calico state, and of kube-proxy's rules, from kernel tables that Felix no longer programs.
Code: `felix/dataplane/linux/int_dataplane.go` (`NewIntDataplaneDriver`).
_Avoid_: GC

## BPF dataplane

BPF mode is not a separate program. It is the same Felix process with `BPFEnabled=true`, reusing the Linux dataplane's main loop and managers, plus C programs that run inside the kernel. Felix and those programs share state through BPF maps and per-attach globals.

### Building blocks

In Felix (Go):

| Building block | Code | Responsible for |
|---|---|---|
| BPF endpoint manager | `felix/dataplane/linux/bpf_ep_mgr.go` (`bpfEndpointManager`) | Attaching programs to every interface, compiling and loading per-endpoint policy programs, owning jump indices and the ifstate map. |
| Attach point | `felix/bpf/tc/attach.go` (`AttachPoint`); `felix/bpf/xdp/attach.go` (`AttachPoint`) | One interface, one hook and the globals to load into its preamble. |
| Programs map cache | `felix/bpf/hook/map.go` (`ProgramsMap`, `Layout`) | Loading each generic object once per object variant and recording which jump-map slot each generic sub-program landed in. |
| Policy program builder | `felix/bpf/polprog/pol_prog_builder.go` (`Builder`) | Compiling tiers, policies and rules into BPF instructions, split into chained policy sub-programs. |
| BPF route manager | `felix/dataplane/linux/bpf_route_mgr.go` (`bpfRouteManager`) | Writing the routes map from route, workload endpoint and interface updates. |
| Kube-proxy replacement | `felix/bpf/proxy/kube-proxy.go` (`StartKubeProxy`); `felix/bpf/proxy/syncer.go` (`Syncer`) | Watching Services and EndpointSlices and writing the NAT frontend, backend, affinity and Maglev maps. |
| Conntrack scanner | `felix/bpf/conntrack/scanner.go` (`Scanner`) | Sweeping the conntrack table periodically through a chain of entry scanners. |
| Entry scanners | `felix/bpf/conntrack/cleanup.go` (`LivenessScanner`, `StaleNATScanner`, `WorkloadRemoveScannerTCP`) | Expiring flows by timeout, removing flows to dead backends, and marking flows of deleted workloads for a TCP reset. |
| BPF IP sets | `felix/bpf/ipsets/ipsets.go` (`NewBPFIPSets`) | Writing IP set members into the IP sets map under a numeric set ID. |
| Failsafe manager | `felix/bpf/failsafes/failsafes.go` (`Manager`) | Writing failsafe ports into the failsafes map. |
| CTLB installer | `felix/bpf/nat/connecttime.go` (`InstallConnectTimeLoadBalancer`) | Loading and attaching the connect-time load balancer's cgroup programs. |
| BPF event poller | `felix/dataplane/linux/bpf_events.go` (`bpfEventPoller`) | Reading the event ring buffer and dispatching events by type to registered sinks. |
| Map set | `felix/bpf/bpfmap/bpf_maps.go` (`Maps`, `IPMaps`, `CommonMaps`) | Creating and pinning every BPF map at startup, per IP family and shared. |

In the kernel (C):

| Building block | Code | Responsible for |
|---|---|---|
| Preamble | `felix/bpf-gpl/tc_preamble.c` (`cali_tc_preamble`) | The only program attached to a TC hook. It copies the globals into per-CPU state and tail-calls the log filter or the main program. |
| Main program | `felix/bpf-gpl/tc.c` (`calico_tc_main`) | Parsing the packet, looking up conntrack and NAT, then taking the established-flow path or tail-calling into policy. |
| Post-policy sub-programs | `felix/bpf-gpl/tc.c` (`calico_tc_skb_accepted_entrypoint`, `calico_tc_skb_new_flow_entrypoint`, `calico_tc_skb_drop`) | Work after policy: conntrack creation, forwarding, policy-verdict events and drop accounting. |
| Slow-path sub-programs | `felix/bpf-gpl/tc.c` (`calico_tc_skb_send_tcp_rst`) | Work moved out of the main program for verifier or cost reasons, such as ICMP replies, TCP resets, IPv4 fragments and Maglev. |
| Policy program | `felix/bpf-gpl/policy_default.c` (`calico_tc_allow`) | Evaluating one interface's rules in one direction. Felix generates it from active policy. |
| XDP program | `felix/bpf-gpl/xdp.c` (`calico_xdp_main`) | Evaluating untracked host endpoint policy before the kernel allocates an skb, and passing accepted packets to TC. |
| CTLB programs | `felix/bpf-gpl/connect_balancer.c` | Rewriting the destination of `connect()` and `sendmsg()` to a service backend. |
| Conntrack cleaner | `felix/bpf-gpl/conntrack_cleanup.c` (`conntrack_cleanup`) | Deleting queued conntrack entries whose timestamps still match. |

### Terms

**BPF program**:
Code that the kernel verifies and runs at a fixed attach point, such as a network interface or a cgroup. Calico's programs are C files in `felix/bpf-gpl` that Felix loads into the kernel.
Code: `felix/bpf-gpl/tc.c` (`calico_tc_main`).
_Avoid_: eBPF script, filter

**BPF map**:
A kernel data structure, such as a hash, array or trie, that BPF programs and Felix both read and write.
Code: `felix/bpf/maps/maps.go` (`MapParameters`).
_Avoid_: map, unqualified

**Verifier**:
The kernel's static checker. It rejects any BPF program it cannot prove terminates and accesses memory safely.
Code: `felix/bpf/polprog/pol_prog_builder.go` (`Builder`).
_Avoid_: bare verification

**BTF**:
BPF Type Format, the type information embedded in a compiled BPF object.
Code: `felix/bpf-gpl/CLAUDE.md`.
_Avoid_: nothing known

**skb**:
The kernel's socket buffer, the structure that represents one packet in the kernel's network stack.
Code: `felix/bpf-gpl/types.h` (`cali_tc_ctx`).
_Avoid_: sk_buff, packet (it is the kernel's buffer structure, not the bytes on the wire)

**Program type**:
The kernel's category for a BPF program, which fixes where it may attach and which context it receives. Calico uses the TC classifier type, XDP and cgroup socket-address programs.
Code: `felix/bpf-gpl/tc.c` (`calico_tc_main`) and `felix/bpf-gpl/xdp.c` (`calico_xdp_main`).
_Avoid_: hook type (that is `hook.Hook`)

**TC program**:
A BPF program of the kernel's traffic-control classifier type, run on one direction of one interface after the kernel has allocated an skb.
Code: `felix/bpf-gpl/tc.c` (`calico_tc_main`).
_Avoid_: filter

**XDP program**:
A BPF program run in the network driver before the kernel allocates an skb. In BPF mode it carries only untracked host endpoint policy.
Code: `felix/bpf-gpl/xdp.c` (`calico_xdp_main`).
_Avoid_: XDP acceleration (that is the `*tables` mode feature)

**cgroup program**:
A BPF program attached to a cgroup that runs inside socket system calls.
Code: `felix/bpf-gpl/connect_balancer.c`.
_Avoid_: socket LB

**Hook**:
The place a program attaches: the TC ingress side of an interface, its TC egress side, or XDP. Relative to the host namespace, not to policy direction.
Code: `felix/bpf/hook/load.go` (`Hook`).
_Avoid_: hook type

**To-host (TC ingress) hook**:
The hook on an interface's kernel ingress side, which sees packets arriving from that interface into the host. For a workload endpoint it sees what the workload sends.
Code: `felix/bpf/hook/load.go` (`Ingress`) and `felix/bpf-gpl/cali_bpf.h` (`CALI_F_TO_HOST`).
_Avoid_: ingress, for a workload endpoint; host ingress

**From-host (TC egress) hook**:
The hook on an interface's kernel egress side, which sees packets leaving the host through that interface. For a workload endpoint it sees what the workload receives.
Code: `felix/bpf/hook/load.go` (`Egress`) and `felix/bpf-gpl/cali_bpf.h` (`CALI_F_FROM_HOST`).
_Avoid_: egress, for a workload endpoint; host egress

**Attach mechanism**:
The kernel API that attaches a TC program: the classic clsact qdisc, TCX (a link-based attach) or netkit (workload netkit devices only).
Code: `felix/bpf/tc/attach.go` (`ResolveAttachType`).
_Avoid_: attach type

**Attach point**:
One interface, one hook and the per-attach globals Felix loads for it.
Code: `felix/bpf/tc/attach.go` (`AttachPoint`).
_Avoid_: endpoint (one endpoint has several attach points)

**Object variant**:
The tuple of hook, IP family, endpoint type, log level, to-host drop and DSR that identifies one precompiled object file. Its type is `hook.AttachType`.
Code: `felix/bpf/hook/load.go` (`AttachType`).
_Avoid_: attach type

**`EndpointType` (BPF)**:
The class of an attach point: workload, host, L3 device, NAT interface or loopback.
Code: `felix/bpf/tc/defs/defs.go` (`EndpointType`).
_Avoid_: attach type (that is the TC, TCX or netkit mechanism), bare endpoint (see the qualifier)

**Data interface**:
An interface that BPF mode treats as a host endpoint without a HostEndpoint resource: the main interface, tunnels and similar.
Code: `felix/dataplane/linux/bpf_ep_mgr.go` (`IfaceTypeData`).
_Avoid_: implicit HEP

**Preamble**:
The small program actually attached to each hook.
Code: `felix/bpf-gpl/tc_preamble.c` (`cali_tc_preamble`).
_Avoid_: main program

**Main program**:
The generic per-packet program behind the preamble.
Code: `felix/bpf-gpl/tc.c` (`calico_tc_main`).
_Avoid_: SubProgTCMain

**Generic sub-program**:
One of the endpoint-independent programs in the generic jump map, indexed by `enum cali_jump_index`, such as the post-policy and slow-path programs. Always qualify "sub-program".
Code: `felix/bpf/hook/map.go` (`SubProg`).
_Avoid_: bare sub-program (it could mean a policy sub-program)

**Policy program**:
The per-interface, per-direction program Felix compiles from active policy.
Code: `felix/dataplane/linux/bpf_ep_mgr.go` (`loadPolicyProgram`).
_Avoid_: rules program, bare sub-program (it could mean a generic sub-program)

**Policy sub-program**:
One slice of a policy program too large for one verifier pass, chained to the next by tail calls.
Code: `felix/bpf/jump/map.go` (`MaxSubPrograms`) and `felix/bpf/polprog/pol_prog_builder.go` (`Builder`).
_Avoid_: sub-program, unqualified

**Default policy program**:
A compile-time allow-all or deny-all policy program that stands in for the generated one.
Code: `felix/bpf-gpl/policy_default.c` (`calico_tc_allow`).
_Avoid_: CALI_TC_DEF_POLICY, policy program (that is the generated one)

**Tail call**:
A jump from one BPF program into another through a jump map slot. It never returns.
Code: `felix/bpf-gpl/jump.h` (`CALI_JUMP_TO`).
_Avoid_: call

**Jump map**:
A BPF map of the program-array type that holds programs by index, and is the target of tail calls. It stores programs, not data.
Code: `felix/bpf-gpl/jump.h` (`cali_jump_map`).
_Avoid_: map, for a jump map

**Generic jump map**:
The jump map of endpoint-independent generic sub-programs: `cali_progs_ing`, `cali_progs_egr` and `xdp_cali_progs`, plus netkit twins. Not the Go cache `hook.ProgramsMap`.
Code: `felix/bpf/hook/map.go` (`ProgramsMap`).
_Avoid_: static jump map

**Policy jump map**:
The jump map of per-endpoint policy programs and log filters: `cali_jump_ing`, `cali_jump_egr` and `xdp_cali_jump`, plus netkit twins.
Code: `felix/bpf/jump/map.go` (`MaxSubPrograms`).
_Avoid_: per-endpoint programs map

**Jump index**:
A slot number in a jump map.
Code: `felix/dataplane/linux/bpf_ep_mgr.go` (`bpfInterfaceJumpIndices`).
_Avoid_: policyIdx, filterIdx

**Continuation**:
The two jump indices (`skb->cb[0]` for allow, `skb->cb[1]` for deny) that say where the policy program goes next.
Code: `felix/bpf-gpl/jump.h` (`__CALI_JUMP_TO_POLICY`).
_Avoid_: allow/deny jump

**Fast path and debug path**:
The two builds of each generic sub-program: one without log statements and one with them, loaded at different indices.
Code: `felix/bpf-gpl/jump.h` (`PROG_PATH`) and `felix/bpf/hook/map.go` (`allocateLayout`).
_Avoid_: fast path, for the established-flow path

**Log filter**:
A pcap expression compiled to BPF that selects which packets take the debug path.
Code: `felix/bpf/filter/filter.go` and `felix/dataplane/linux/bpf_ep_mgr.go` (`loadTCLogFilter`).
_Avoid_: filter, unqualified

**Globals**:
The per-attach-point configuration (`struct cali_tc_global_data`), held in the preamble's read-only data.
Code: `felix/bpf-gpl/globals.h` (`cali_tc_global_data`).
_Avoid_: config map

**Globals flags**:
The runtime feature bits (`CALI_GLOBALS_*`) held in the globals, such as `IFACE_ENCAPS`, `REDIRECT_PEER` and `FLOWLOGS_ENABLED`.
Code: `felix/bpf-gpl/globals.h` (`CALI_GLOBALS_IFACE_ENCAPS`).
_Avoid_: compile flags

**Compile flags**:
The compile-time constants (`CALI_F_*`) that pick an object variant (host or workload endpoint, direction, DSR, L3, XDP).
Code: `felix/bpf-gpl/cali_bpf.h` (`CALI_COMPILE_FLAGS`).
_Avoid_: globals flags

**`prog_flags`**:
Load-time flags in a frozen read-only section (`struct prog_flags`), currently only `no_trace_printk`.
Code: `felix/bpf-gpl/globals.h` (`prog_flags`).
_Avoid_: globals (they are a separate section)

**State map**:
A two-slot per-CPU array (`cali_state`). Slot 0 holds the per-packet state and slot 1 holds the copied globals plus header scratch space.
Code: `felix/bpf-gpl/jump.h` (`cali_state`).
_Avoid_: per-CPU state

**ifstate map**:
The hash (`cali_iface`) from interface index to interface flags (ready, workload endpoint, host endpoint, encapsulation kind) and per-direction policy indices.
Code: `felix/bpf-gpl/ifstate.h` (`cali_iface`) and `felix/bpf/ifstate/map.go` (`MapParams`).
_Avoid_: iface map, interface state map

**`ifaceReadiness`**:
Whether a workload endpoint's programs are attached for an IP family.
Code: `felix/dataplane/linux/bpf_ep_mgr.go` (`ifaceReadiness`).
_Avoid_: bare ready (it means several things)

**Attach gap**:
The window between an interface appearing and its programs attaching.
Code: `felix/bpf-gpl/fib_common.h` (`fib_approve`).
_Avoid_: nothing known

**skb mark**:
The bits of the packet mark in `0x1FF00000` that carry signals between BPF programs and `*tables`.
Code: `felix/bpf-gpl/cali_bpf.h` (`calico_skb_mark`).
_Avoid_: mark bits (that is the `*tables` allocation)

**Bypass mark**:
The skb mark `CALI_SKB_MARK_BYPASS`, which marks a packet whose flow both conntrack legs have approved.
Code: `felix/bpf-gpl/cali_bpf.h` (`CALI_SKB_MARK_BYPASS`).
_Avoid_: bare bypass (the `BYPASS_FWD` and `BYPASS_XDP` codes are separate values)

**Fallthrough**:
Handing a packet to the kernel's own conntrack, marked with `CALI_SKB_MARK_FALLTHROUGH`.
Code: `felix/bpf-gpl/cali_bpf.h` (`CALI_SKB_MARK_FALLTHROUGH`).
_Avoid_: bypass (that is the opposite: skip policy and keep the flow in BPF)

**SkipFIB**:
Skipping the BPF FIB (route) lookup and letting the host network stack route the packet.
Code: `felix/bpf-gpl/cali_bpf.h` (`CALI_SKB_MARK_SKIP_FIB`).
_Avoid_: SKIP_FIB

**Forward-or-defer decision**:
Whether BPF forwards a packet itself or hands it to the host network stack.
Code: `felix/design/bpf-overview.md`.
_Avoid_: fallthrough (one specific mark)

**BPF conntrack table**:
Calico's own LRU-hash connection tracker (`cali_v4_ct`, `cali_v6_ct`), independent of netfilter conntrack. Say "kernel conntrack" for the netfilter one.
Code: `felix/bpf-gpl/conntrack_types.h` (`calico_ct_key`) and `felix/bpf/conntrack/v4/map.go` (`TypeNATReverse`).
_Avoid_: conntrack, unqualified, near `*tables`

**Conntrack entry type**:
One of `NORMAL` (the single entry of a non-NAT flow), `NAT_FWD` (a pre-NAT stub) or `NAT_REV` (the post-NAT tracking entry).
Code: `felix/bpf/conntrack/v4/map.go` (`TypeNATReverse`).
_Avoid_: bare conntrack (say BPF conntrack or kernel conntrack)

**Tracking entry**:
The entry that holds a flow's state. For a flow with NAT it is the `NAT_REV` entry, otherwise the normal entry.
Code: `felix/design/bpf-conntrack-flowstate.md`.
_Avoid_: forward entry

**Leg**:
One direction of a conntrack entry (`a_to_b` or `b_to_a`), with its counters, TCP flags, approval and interface index.
Code: `felix/bpf-gpl/conntrack_types.h` (`calico_ct_leg`).
_Avoid_: side

**`CALI_CT_LEG_APPROVED`**:
The conntrack leg flag meaning the policy program on that leg's side allowed the flow.
Code: `felix/bpf-gpl/conntrack_types.h` (`CALI_CT_LEG_APPROVED`).
_Avoid_: bypass mark (that is set once both legs are approved)

**Opener leg**:
The leg that started the flow, marked `CALI_CT_LEG_OPENER`.
Code: `felix/bpf-gpl/conntrack_types.h` (`CALI_CT_LEG_OPENER`).
_Avoid_: bare forward (`NAT_FWD` is an entry type, not a direction)

**Forwarding hint**:
A leg's recorded interface index.
Code: `felix/bpf-gpl/conntrack_types.h` (`ifindex_fwd`).
_Avoid_: ifindex_fwd

**`calico_ct_result_type`**:
The outcome of a conntrack lookup (`CALI_CT_*`), such as a new flow, a mid-flow miss or an established flow with its bypass and NAT variants.
Code: `felix/bpf-gpl/conntrack_types.h` (`calico_ct_result_type`).
_Avoid_: nothing known

**Conntrack flags**:
Per-flow decisions stored in a conntrack entry (`CALI_CT_FLAG_*`), such as `SVC_SELF`, `MAGLEV`, `SKIP_FIB` and `NP_FWD`.
Code: `felix/bpf-gpl/conntrack_types.h` (`CALI_CT_FLAG_SKIP_FIB`).
_Avoid_: leg flags (the `CALI_CT_LEG_*` flags are separate)

**Scan verdict**:
An entry scanner's answer for one conntrack entry: `OK`, `Delete` or `SendRST`.
Code: `felix/bpf/conntrack/scanner.go` (`ScanVerdict`).
_Avoid_: policy verdict (that is allow or deny)

**NAT frontend map**:
The map (`cali_v4_nat_fe`) from a service's virtual address, port, protocol and source CIDR to a service ID and backend count.
Code: `felix/bpf-gpl/nat_types.h` (`calico_nat_key`) and `felix/bpf/nat/maps.go` (`FrontendMap`).
_Avoid_: frontend map

**NAT backend map**:
The map (`cali_v4_nat_be`) from a service ID and ordinal to one backend's address and port.
Code: `felix/bpf-gpl/nat_types.h` (`calico_nat_dest`) and `felix/bpf/nat/maps.go` (`BackendMap`).
_Avoid_: backend map, bare backend (see the qualifier)

**Service ID**:
A per-service number that indexes the service's block of the backend map, shared with its derived NodePort and LoadBalancer frontends.
Code: `felix/design/bpf-services.md`.
_Avoid_: svcID

**Affinity map**:
The map (`cali_v4_nat_aff`) recording which backend a client was given, for services with session affinity.
Code: `felix/bpf/nat/maps.go` (`AffinityMap`).
_Avoid_: block affinity (that is an IPAM term), session affinity (that is the Service setting)

**Maglev LUT**:
The per-service consistent-hash lookup table (`cali_v4_mglv`).
Code: `felix/bpf/nat/maps.go` (`MaglevMap`) and `felix/bpf/consistenthash/`.
_Avoid_: table, unqualified

**Send/recv-msg map**:
The map (`cali_v4_srmsg`) that holds a socket's original service address for the connect-time load balancer.
Code: `felix/bpf-gpl/sendrecv.h` (`sendrec_key`).
_Avoid_: reverse-SNAT map

**Routes map**:
The longest-prefix-match trie (`cali_v4_routes`) from CIDR to route flags (`CALI_RT_*`) and next hop or interface index. Not the kernel's routing table.
Code: `felix/bpf-gpl/routes.h` (`cali_rt_key`) and `felix/bpf/routes/map.go` (`MapParameters`).
_Avoid_: BPF route table, routing table (that is the kernel's)

**ARP map**:
An LRU cache (`cali_v4_arp`) of layer-2 headers keyed by IP address and interface index.
Code: `felix/bpf-gpl/arp.h` (`arp_key`) and `felix/bpf/arp/map.go` (`MapParams`).
_Avoid_: neighbor table (that is the kernel's)

**Allowed source prefixes**:
The trie (`cali_v4_sprefix`) of interface index and CIDR pairs that a workload may use as a source address beyond its own IPs.
Code: `felix/bpf/allowsources/map.go` (`MapParameters`).
_Avoid_: sprefix, allow-sources

**Failsafes map**:
The map (`cali_v4_fsafes`) of failsafe ports that BPF always allows on host endpoints.
Code: `felix/bpf/failsafes/failsafes_map.go` (`MapParams`).
_Avoid_: calico_failsafe_ports

**IP fragment maps**:
The three maps used for IPv4 reassembly: `cali_v4_frags` (reassembly), `cali_v4_frgtmp` (per-CPU scratch space) and `cali_v4_frgfwd` (forwarding by fragment ID).
Code: `felix/bpf-gpl/ip_v4_fragment.h`.
_Avoid_: nothing known

**QoS maps**:
`cali_qos`, a packet-rate token bucket guarded by a spinlock, and `cali_qos_conn`, for connection limits.
Code: `felix/bpf-gpl/qos.h`.
_Avoid_: nothing known

**Event ring buffer**:
The BPF ring buffer (`cali_rb_evnt`) through which programs send typed events to Felix.
Code: `felix/bpf-gpl/ringbuf.h` and `felix/bpf/events/events.go` (`Events`).
_Avoid_: perf events

**Policy-verdict event**:
The event (`EVENT_POLICY_VERDICT`) that a BPF program sends to Felix on the ring buffer.
Code: `felix/bpf-gpl/events.h` (`event_flow_log`).
_Avoid_: flow log (the aggregated record that Felix and Goldmane produce)

**Map version**:
An integer suffixed to a pinned map's name, which changes with the map's layout.
Code: `felix/bpf/maps/maps.go` (`VersionedName`).
_Avoid_: bare version (v1, v2 and v3 name API versions)

**Pin**:
A file under `/sys/fs/bpf` that keeps a map or link alive across Felix restarts.
Code: `felix/bpf/bpfdefs/defs.go` (`GlobalPinDir`).
_Avoid_: pinned map, for the file

**Kernel lockdown**:
A kernel mode (confidentiality) in which tracing is off.
Code: `felix/bpf/lockdown.go`.
_Avoid_: nothing known

**RPF**:
Reverse-path filtering, enforced inside the BPF programs for workload and host endpoints.
Code: `felix/bpf-gpl/rpf.h` (`wep_rpf_check`).
_Avoid_: rp_filter (that is the kernel's setting, which stays relaxed)

**`bpfNetworkBootstrap`**:
The mode in which the `ebpf-bootstrap` init container programs the API server's Service into the NAT maps.
Code: `felix/bpf/proxy/syncer.go` (`bpfNetworkBootstrap`).
_Avoid_: ebpf-bootstrap (that is the init container)

## Words that need a qualifier

These extend the [root table](../GLOSSARY.md#words-that-need-a-qualifier) with meanings inside Felix.

| Word | Meanings in play | Say |
|---|---|---|
| in-sync | the syncer's end of snapshot, the dataplane's first-clean-apply reply, the interface monitor's report, the in-sync gate | datastore in-sync, dataplane in-sync, interface monitor in-sync, in-sync gate |
| resync | the syncer's snapshot phase, a reconciling driver's read-back | datastore resync, dataplane resync |
| flush | the graph's deferred work, the event sequencer's emission | graph flush, sequencer flush |
| dataplane driver | the `DataplaneDriver` process boundary, the mode selector, the reconciling layer, an external driver process | dataplane driver, driver selector, reconciling driver, external dataplane driver |
| node | a calculation node, a trie node in the longest-prefix route lookup, a host, the Node resource | calculation node, trie node, host, Node |
| sub-program | a generic sub-program, a policy sub-program | generic sub-program, policy sub-program |
| attach type | the `BPFAttachType` setting, the `hook.AttachType` tuple, the kernel's expected attach type | attach mechanism, object variant |
| XDP | the BPF dataplane's XDP program, iptables-mode XDP acceleration | XDP program, iptables-mode XDP |
| conntrack | the BPF conntrack table, netfilter conntrack | BPF conntrack table, kernel conntrack |
| ingress and egress | policy direction relative to an endpoint, the kernel hook direction | ingress policy and egress policy, to-host (TC ingress) hook and from-host (TC egress) hook |
