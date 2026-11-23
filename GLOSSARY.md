# Calico glossary

This file fixes the vocabulary the monorepo uses: one canonical word per concept, plus the synonyms to stop reaching for. Terms used by two or more components live here. Terms that belong to one component live in `<component>/GLOSSARY.md`, beside that component's `DESIGN.md`, and each area below links to them. Architecture belongs in [`DESIGN.md`](DESIGN.md).

A term listed under `_Avoid_` is not a rename order. Existing identifiers keep their names until you are editing that code anyway; the glossary governs new code, new comments, commit messages, and PR descriptions.

Agents never coin a term. A new term is named by a person, checked against these glossaries for collisions, and added here or in the component glossary by the PR that introduces it.

Each entry ends with a code anchor: a repo-relative path and, where one exists, the symbol that defines the term.

## Structure terms

These words describe how the design docs and component glossaries are organized.

**Component**:
A separately running program, such as Felix, Typha, confd or kube-controllers. Bare "component" always means this; the other meanings are in the qualifier table below.
Code: `cmd/calico/component.go` (`newComponentCommand`).
_Avoid_: "component" for a render component, an image, or a subcommand

**Building block**:
A named piece inside a component, in the code's own words, such as a Felix dataplane manager or one kube-controllers controller.
Code: `felix/DESIGN.md`.
_Avoid_: module, subsystem

**Layer**:
One level of nesting of building blocks, written `A > B`.
Code: `felix/DESIGN.md`.
_Avoid_: tier (that is a policy term)

**Contract**:
What crosses between two components or two building blocks: a protocol, a protobuf API, or a resource both sides read.
Code: `felix/proto/felixbackend.proto` (`ToDataplane`).
_Avoid_: interface, when a wire format is meant

**Shared library**:
Code that several components run, such as libcalico-go or the Typha sync client.
Code: `libcalico-go/lib/backend/api/api.go` (`Syncer`).
_Avoid_: component

## Language

### Datastore and API

Library internals (watcher caches, per-kind KDD clients) are in [libcalico-go/GLOSSARY.md](libcalico-go/GLOSSARY.md). The Typha wire protocol and sync pipeline are in [typha/GLOSSARY.md](typha/GLOSSARY.md). The calicoctl subcommands that move data between datastores are in [calicoctl/GLOSSARY.md](calicoctl/GLOSSARY.md). The [Installation](operator/GLOSSARY.md#installation) resource is defined in [operator/GLOSSARY.md](operator/GLOSSARY.md). The Calico apiserver's registry terms are in [apiserver/GLOSSARY.md).

**Datastore**:
The store of record for Calico configuration and state: the Kubernetes API (KDD) or etcdv3. A cluster uses exactly one.
Code: `libcalico-go/lib/apiconfig/apiconfig.go` (`DatastoreType`).
_Avoid_: backend, database

**KDD**:
The Kubernetes datastore driver. It stores some Calico resources as CRDs and synthesizes others from core Kubernetes objects.
Code: `libcalico-go/lib/backend/k8s/client.go` (`KubeClient`).
_Avoid_: k8s backend, CRD mode

**etcdv3 mode**:
The datastore that writes every Calico resource to etcd, with no Kubernetes API involved.
Code: `libcalico-go/lib/backend/etcdv3/etcdv3.go` (`NewEtcdV3Client`).
_Avoid_: etcd mode, legacy mode

**v3 API**:
The public `projectcalico.org/v3` resource types, such as GlobalNetworkPolicy and IPPool. Any other API group is named in full.
Code: `api/pkg/apis/projectcalico/v3/` (`NetworkPolicy`).
_Avoid_: bare "v3", CRD (that is one way a resource is stored, not what it is)

**Backing API group**:
The API group in which a KDD cluster stores Calico resources as CRDs: `crd.projectcalico.org/v1` or `projectcalico.org/v3`. `CALICO_API_GROUP` picks one, and with no setting the library discovers it from the API server.
Code: `libcalico-go/lib/backend/k8s/resources/apigroups.go` (`BackingAPIGroup`), `libcalico-go/lib/backend/k8s/discovery.go` (`BackendAPIGroup`, `UsingV3CRDs`), `operator/pkg/apigroup/apigroup.go`.
_Avoid_: API version, bare "v1 CRDs", bare "v3 CRDs", "v1 CRD group", "v3 CRD group"

**Aggregated v3 API**:
The `projectcalico.org/v3` API as served by the Calico apiserver through the Kubernetes API aggregation layer, which runs when `crd.projectcalico.org/v1` CRDs back the datastore. Discovery sees both groups in this case and picks `crd.projectcalico.org/v1` as the backing API group; kube-apiserver can instead serve `projectcalico.org/v3` directly from CRDs, which needs no Calico apiserver.
Code: `apiserver/pkg/apiserver/apiserver.go` (`ProjectCalicoServer`), `libcalico-go/lib/backend/k8s/discovery.go` (`UsingV3CRDs`).
_Avoid_: the aggregated API, v3 apiserver, "v3 API" when the serving path matters

**Internal API resource**:
A Calico resource in `internalapi` that is not public: Node, WorkloadEndpoint, IPAMBlock, IPAMHandle, IPAMConfig, BlockAffinity and LiveMigration.
Code: `libcalico-go/lib/apis/internalapi/README.md`.
_Avoid_: private resource, hidden CRD

**Synthesized resource**:
A model object KDD derives from a core Kubernetes object instead of storing it: WorkloadEndpoint from Pod, Profile from Namespace or ServiceAccount, KubernetesService, KubernetesEndpointSlice.
Code: `libcalico-go/lib/backend/k8s/client.go` (`registerResourceClient`).
_Avoid_: derived CRD

**KVPair**:
A typed model key, its value (nil means deleted), a revision, and an optional UID and TTL.
Code: `libcalico-go/lib/backend/model/keys.go` (`KVPair`).
_Avoid_: update (that is a KVPair plus an update type), key-value pair (a KVPair also carries a revision, UID and TTL)

**Model key**:
A parsed datastore key that renders a unique default path. It is either a v1-model key or a `ResourceKey`.
Code: `libcalico-go/lib/backend/model/keys.go` (`Key`).
_Avoid_: datastore key (that is the rendered default path), v1 key (only one of the two kinds)

**ResourceKey**:
The model key for a v3 resource: kind, namespace and name.
Code: `libcalico-go/lib/backend/model/resource.go` (`ResourceKey`).
_Avoid_: v3 key

**Default path**:
The `/calico/...` etcd key string for a model key, also Typha's wire encoding of keys.
Code: `libcalico-go/lib/backend/model/keys.go` (`KeyToDefaultPath`).
_Avoid_: etcd key (the path is only a string rendering, and the Kubernetes datastore stores nothing at it), key path

**v1 model**:
The internal key and value shapes in `libcalico-go/lib/backend/model`, such as `PolicyKey`, `WorkloadEndpointKey` and `HostConfigKey`, which update processors produce. It is not an API version anyone can request.
Code: `libcalico-go/lib/backend/syncersv1/updateprocessors/doc.go`.
_Avoid_: backend model, v1 API, legacy model, bare "v1"

**Datastore syncer**:
A building block (`api.Syncer`) that lists and watches a fixed list of resource types, converts them with update processors, and streams KVPair updates plus sync status to one `SyncerCallbacks`. Typha runs one per syncer type, and Felix, confd, calico-node, kube-controllers (its DataFeed) and the Calico apiserver each run one locally; Felix can take the same stream from Typha's sync client instead of its local `felixsyncer`.
Code: `libcalico-go/lib/backend/api/api.go` (`Syncer`), `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`watcherSyncer`), `felix/daemon/daemon.go` (`Run`).
_Avoid_: watcher, sync loop, v1 syncer, bare "syncer" outside datastore context

**Syncer output**:
The stream of KVPairs a datastore syncer emits, which mixes v1-model keys from update processors with v3 `ResourceKey`s for pass-through kinds.
Code: `libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go` (`New`), `libcalico-go/lib/backend/syncersv1/updateprocessors/doc.go`.
_Avoid_: v1 updates, v1 model stream, "v1 model" for the whole stream

**Pass-through kind**:
A v3 kind in a syncer's resource list that has no update processor, so the syncer forwards it as a v3 `ResourceKey` instead of converting it to the v1 model. BGPConfiguration, BGPPeer, BGPFilter and LiveMigration are examples; the `DataplanePassthru` calculation node is a different thing.
Code: `libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go` (`New`), `libcalico-go/lib/backend/syncersv1/bgpsyncer/bgpsyncer.go` (`New`), `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`ResourceType`), `felix/calc/dataplane_passthru.go` (`DataplanePassthru`).
_Avoid_: DataplanePassthru (that is a calculation node), passthrough (that is also an operator render component)

**Syncer type**:
The name a client sends in its hello message to pick the stream it receives. It is `felix`, `bgp`, `tunnel-ip-allocation` or `node-status`.
Code: `typha/pkg/syncproto/sync_proto.go` (`SyncerType`).
_Avoid_: syncer kind (kind is a resource word)

**watchersyncer**:
libcalico-go's generic datastore syncer, which merges one watcher cache per resource type into one `api.Syncer`.
Code: `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`New`).
_Avoid_: informer

**Update processor**:
A `SyncerUpdateProcessor` that converts one v3 KVPair into zero or more v1-model KVPairs.
Code: `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`SyncerUpdateProcessor`).
_Avoid_: converter, translator

**SyncerCallbacks**:
The consumer interface of a datastore syncer: `OnStatusUpdated` and `OnUpdates`.
Code: `libcalico-go/lib/backend/api/api.go` (`SyncerCallbacks`).
_Avoid_: nothing known

**Sync status**:
`WaitForDatastore`, `ResyncInProgress` or `InSync`.
Code: `libcalico-go/lib/backend/api/api.go` (`SyncStatus`).
_Avoid_: syncer status, bare in-sync (that is only one of the three values)

**Datastore in-sync**:
The sync status reached once every watcher cache has delivered its initial list. Consumers hold off kernel writes and deletions until they see it.
Code: `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`watcherSyncer`).
_Avoid_: caught up, ready, synced, bare "in-sync"

**Datastore resync**:
The datastore syncer's snapshot phase, `ResyncInProgress`.
Code: `libcalico-go/lib/backend/api/api.go` (`ResyncInProgress`).
_Avoid_: bare "resync"

**Dedupe buffer**:
A queue between a datastore syncer (or sync client) and its consumer that replaces a queued value when a newer one arrives for the same key. It bounds in-flight data to the size of the datastore, and it may reorder updates for different keys.
Code: `libcalico-go/lib/backend/syncersv1/dedupebuffer/dedupe_buffer.go` (`DedupeBuffer`).
_Avoid_: cache (Typha's snapshot cache is a different thing), queue (it replaces entries rather than only queuing them)

**Sync client**:
`SyncerClient`, the client end of the Typha protocol, presenting the same `SyncerCallbacks` as a local datastore syncer.
Code: `typha/pkg/syncclient/sync_client.go` (`SyncerClient`).
_Avoid_: Typha client

**ClusterInformation**:
The `default` singleton holding CalicoVersion, ClusterGUID and `DatastoreReady`.
Code: `libcalico-go/lib/clientv3/client.go` (`EnsureInitialized`).
_Avoid_: ClusterInfo (the kubectl short name), cluster info

**Datastore ready flag**:
`ClusterInformation.spec.datastoreReady`, delivered to Felix as `ReadyFlagKey`. When it is false Felix restarts and CNI is blocked.
Code: `libcalico-go/lib/backend/model/felixconfig.go` (`ReadyFlagKey`).
_Avoid_: readiness (that is health)

**Datastore lock**:
Setting `ClusterInformation.spec.datastoreReady` to false so components pause before a migration, and clearing it afterwards. The kube-controllers migration controller locks the `crd.projectcalico.org/v1` datastore before copying and unlocks it on rollback, and `calicoctl` has lock and unlock commands for the etcd-to-KDD migration, which do not stop users from updating or creating Calico resources.
Code: `kube-controllers/pkg/controllers/migration/controller.go` (`lockV1Datastore`), `calicoctl/calicoctl/commands/datastore/migrate/lock.go` (`Lock`).
_Avoid_: bare "lock" (a Go mutex)

**Dry run**:
A context flag asking the backend to validate a write without persisting it, and to refuse if it cannot.
Code: `libcalico-go/lib/backend/api/dryrun.go` (`WithDryRun`).
_Avoid_: nothing known

**Calico validation**:
libcalico-go's semantic validation of v3 resources, applied by clientv3 and by the Calico apiserver's dry-run `Store`. The admission webhooks and the Felix and Typha `ValidationFilter`s apply it too.
Code: `libcalico-go/lib/validator/v3/validator.go` (`Validate`).
_Avoid_: schema validation (CRD OpenAPI and CEL validation are separate), validator

**FelixConfiguration**:
The v3 resource behind Felix's global, selector-scoped and per-host datastore config sources. A selector-scoped FelixConfiguration applies only to hosts whose Node labels match its selector.
Code: `felix/config/config_params.go` (`Source`).
_Avoid_: FelixConfig, felix config (that is every parameter from every source, not this resource)

**v1-to-v3 CRD migration**:
The move of Calico resources from `crd.projectcalico.org/v1` CRDs to `projectcalico.org/v3` CRDs, triggered and reported by the `DatastoreMigration` resource named `v1-to-v3` and run by the kube-controllers migration controller. It is not the etcd-to-KDD migration that `calicoctl` runs.
Code: `kube-controllers/pkg/apis/migration/v1/types.go` (`DatastoreMigration`), `kube-controllers/pkg/controllers/migration/controller.go`, `operator/pkg/controller/migration/datastoremigration/types.go`.
_Avoid_: bare "datastore migration", unqualified "CRD migration"

**etcd-to-KDD migration**:
calicoctl's move of a cluster's Calico resources and IPAM state from etcdv3 to the Kubernetes datastore, run with `calicoctl datastore migrate`. It renames each Node from its v3.Node name to the node name in its `k8s` orchestrator reference, and it is not the v1-to-v3 CRD migration, which kube-controllers runs.
Code: `calicoctl/calicoctl/commands/datastore_command.go`, `calicoctl/calicoctl/commands/datastore/migrate/export.go` (`Export`), `calicoctl/calicoctl/commands/datastore/migrate/import.go` (`Import`).
_Avoid_: bare "datastore migration", KDD migration

### Endpoints and hosts

The [Auto host endpoint](kube-controllers/GLOSSARY.md#auto-host-endpoint) that kube-controllers creates is in [kube-controllers/GLOSSARY.md](kube-controllers/GLOSSARY.md).

**Workload endpoint** (WEP):
A Calico-managed interface belonging to a workload, one per pod veth or netkit device.
Code: `felix/proto/felixbackend.proto` (`WorkloadEndpointUpdate`).
_Avoid_: bare "endpoint", pod interface, veth

**Host endpoint** (HEP):
A Calico-managed host interface used to apply policy to traffic entering or leaving the host.
Code: `felix/proto/felixbackend.proto` (`HostEndpointUpdate`).
_Avoid_: bare "endpoint", node interface

**Node**:
The Calico resource for one host, carrying its BGP spec, tunnel addresses and WireGuard key. Write "Kubernetes Node" for the Kubernetes object and "host" for the machine.
Code: `libcalico-go/lib/apis/internalapi/node.go` (`Node`).
_Avoid_: bare "node"

**Node name**:
The name of the Kubernetes Node. A v3.Node records it in its `k8s` orchestrator reference.
Code: `libcalico-go/lib/backend/model/workloadendpoint.go` (`WorkloadEndpointKey`), `libcalico-go/lib/apis/internalapi/node.go` (`OrchRef`).
_Avoid_: hostname, host (these name the machine)

**v3.Node name**:
The name of the Calico Node resource. It almost always equals the node name, though in some etcdv3 clusters it differs. The model key fields `Hostname` (workload endpoints, host config), `Host` (block affinities, BGP nodes) and `Node` (v3 specs) all hold it, and IPAM calls it the host.
Code: `libcalico-go/lib/backend/model/workloadendpoint.go` (`WorkloadEndpointKey`), `libcalico-go/lib/backend/model/block_affinity.go` (`BlockAffinityKey`), `libcalico-go/lib/backend/model/bgp_node.go` (`BGPNodeKey`).
_Avoid_: node name, when the Calico Node is meant; hostname, host

**Calico node address**:
The primary address recorded on a Calico Node resource, in `Node.spec.bgp.ipv4Address` or `ipv6Address`, with its prefix. BIRD uses it as router ID and next hop, and Felix and VXLAN use it too. It is not one of the Kubernetes Node's own internal or external IPs.
Code: `node/pkg/lifecycle/startup/startup.go` (`configureIPsAndSubnets`), `libcalico-go/lib/backend/syncersv1/updateprocessors/bgpnodeprocessor.go`.
_Avoid_: BGP IP, NodeIP, node IP, bare "node address", host address

**Tunnel address**:
A per-node address, allocated from IPAM, for the IPIP, VXLAN or WireGuard device and stored on the Node resource.
Code: `node/pkg/allocateip/allocateip.go` (`assignHostTunnelAddr`, `updateNodeWithAddress`).
_Avoid_: host tunnel address, VTEP (that is VXLAN only)

**VTEP**:
A VXLAN tunnel endpoint: the per-node tunnel IP, MAC and host IP that VXLAN traffic is encapsulated to.
Code: `felix/proto/felixbackend.proto` (`VXLANTunnelEndpointUpdate`), `felix/vxlanfdb/vxlan_fdb.go` (`VTEP`).
_Avoid_: tunnel endpoint, vtep

**Endpoint status directory**:
The directory, set by `EndpointStatusPathPrefix`, where Felix writes one endpoint status file for each workload endpoint it has programmed. The CNI plugin watches it to delay a pod's start until its endpoint is programmed, and confd's local workload peering reads it too.
Code: `felix/statusrep/status_file_reporter.go` (`EndpointStatusFileReporter`), `felix/config/config_params.go` (`EndpointStatusPathPrefix`), `cni-plugin/pkg/types/types.go` (`EndpointStatusDir`).
_Avoid_: policy directory

**Endpoint status file**:
A per-workload file Felix writes in the endpoint status directory once it has programmed the endpoint. Its name derives from the WorkloadEndpoint key, and the CNI plugin's policy wait and confd's local BGP peer watcher read it.
Code: `libcalico-go/lib/epstatusfile/status_file_writer.go` (`GetDirStatus`), `libcalico-go/lib/names/workloadendpointstatus.go` (`WorkloadEndpointKeyToStatusFilename`), `cni-plugin/pkg/wait/wait.go` (`ForEndpointReadyWithTimeout`), `confd/pkg/backends/calico/local_bgp_peer_watcher.go` (`NewLocalBGPPeerWatcher`).
_Avoid_: policyDir

**Live migration**:
Moving a KubeVirt or OpenStack VM between hosts. IPAM, Felix and BIRD track an active and an alternate owner and a route priority during the move.
Code: `felix/calc/live_migration_calculator.go` (`LiveMigrationCalculator`), `libcalico-go/lib/backend/model/block.go` (`ActiveOwnerAttrs`).
_Avoid_: migration (that is also CRD migration, etcd-to-KDD migration and Flannel migration)

### Policy

Felix's policy calculation (the calculation graph, IP set member index, label parents) is in [felix/GLOSSARY.md](felix/GLOSSARY.md). Dikastes terms (check providers, policy scope, the policy store) are in [app-policy/GLOSSARY.md](app-policy/GLOSSARY.md).

**Network policy**:
A Calico policy resource selecting endpoints with ordered ingress and egress rules. NetworkPolicy is namespaced, GlobalNetworkPolicy is cluster-wide.
Code: `libcalico-go/lib/backend/model/policy.go` (`PolicyKey`).
_Avoid_: ACL, firewall rule

**Policy name**:
The `metadata.name` of a policy resource. A policy's tier is the separate `spec.tier` field.
Code: `api/pkg/apis/projectcalico/v3/networkpolicy.go` (`NetworkPolicySpec`).
_Avoid_: v1 name

**Policy name migration**:
The kube-controllers controller, and the matching `calicoctl datastore migrate-policy-names` command for etcdv3 mode, that renames policies in the default tier whose stored policy name carries a `default.` tier prefix from before v3.32. The command reuses kube-controllers' `MigratePolicyKVP`.
Code: `kube-controllers/pkg/controllers/networkpolicy/policy_name_migrator.go` (`policyMigrator`), `calicoctl/calicoctl/commands/datastore/migrate/policyname.go` (`MigratePolicyNames`).
_Avoid_: legacy name fix, bare "migration"

**Kubernetes network policy**:
The upstream `networking.k8s.io` resource, which KDD presents as the model-only `KubernetesNetworkPolicy`.
Code: `libcalico-go/lib/backend/model/kubenetworkpolicy.go` (`KindKubernetesNetworkPolicy`).
_Avoid_: k8s policy, native policy

**Tier**:
An ordered group of Calico policies. `kube-admin` (1000), `default` (1,000,000) and `kube-baseline` (10,000,000) always exist.
Code: `libcalico-go/lib/names/policy.go` (`DefaultTierName`), `api/pkg/apis/projectcalico/v3/tier.go` (`KubeAdminTierOrder`).
_Avoid_: policy group, layer

**Profile**:
A label and rule set attached to endpoints. KDD derives one per Namespace (`kns.`) and per ServiceAccount (`ksa.`), plus `projectcalico-default-allow`.
Code: `libcalico-go/lib/backend/k8s/conversion/constants.go` (`NamespaceLabelPrefix`).
_Avoid_: default policy, namespace policy

**Rule**:
One match-and-action entry in a policy or a profile.
Code: `api/pkg/apis/projectcalico/v3/policy_common.go` (`Rule`).
_Avoid_: ACL entry, filter

**Entity rule**:
The source or destination match block of a rule.
Code: `api/pkg/apis/projectcalico/v3/policy_common.go` (`EntityRule`).
_Avoid_: nothing known

**Policy rule action**:
A rule's `Allow`, `Deny`, `Log` or `Pass`. `Pass` continues evaluation at the next tier.
Code: `api/pkg/apis/projectcalico/v3/policy_common.go` (`Action`).
_Avoid_: verdict, bare "action"

**Policy direction**:
Ingress or egress relative to the endpoint. The v1 model calls them `InboundRules` and `OutboundRules`.
Code: `libcalico-go/lib/backend/model/policy.go` (`Policy`), `felix/bpf-gpl/cali_bpf.h` (`CALI_TC_INGRESS`).
_Avoid_: bare "ingress" next to a kernel hook

**Selector**:
Calico's own label expression deciding which endpoints a policy, rule or profile applies to.
Code: `felix/labelindex/labelrestrictionindex/label_restriction_index.go` (`LabelRestrictionIndex`).
_Avoid_: label selector (that is the Kubernetes construct), matcher

**Named port**:
A port that a rule references by name and that resolves to IP-port members.
Code: `felix/calc/rule_scanner.go` (`RuleScanner`).
_Avoid_: port name (that is only the name string, not the resolved IP-port members)

**Network set** (netset):
A named set of CIDRs that rules can select. NetworkSet is namespaced, GlobalNetworkSet is cluster-wide.
Code: `felix/labelindex/named_port_index.go` (`NewSelectorAndNamedPortIndex`).
_Avoid_: IP set, CIDR list, ns

**IP set**:
The members (IPs, CIDRs, IP-port pairs) that match one selector, named port or service, computed by the calculation graph and rendered as an ipset, an nft set or a BPF map.
Code: `felix/proto/felixbackend.proto` (`IPSetUpdate`).
_Avoid_: ipset (that is the tool), address group

**Staged policy**:
A policy evaluated for reporting only and never enforced.
Code: `api/pkg/apis/projectcalico/v3/policy_common.go` (`StagedAction`).
_Avoid_: dry-run policy, preview policy, pending policy

**Staged action**:
`Set`, `Delete`, `Learn` or `Ignore`: what a staged policy would do to its enforced counterpart.
Code: `api/pkg/apis/projectcalico/v3/policy_common.go` (`StagedAction`).
_Avoid_: policy rule action (that is Allow, Deny, Log or Pass)

**Pending policy trace**:
The part of a policy trace computed with staged policies treated as enforced. In the protobuf it is `pending_policies`, and Dikastes computes it with `StagedAsEnforced`.
Code: `goldmane/proto/api.proto` (`PolicyTrace`), `app-policy/checker/check.go` (`StagedAsEnforced`).
_Avoid_: staged trace; bare "pending" (staged policy is the resource, and pending also means other things)

**Performance hint**:
The policy field whose `AssumeNeededOnEveryNode` value makes Felix program the policy on a node where nothing local selects it.
Code: `api/pkg/apis/projectcalico/v3/networkpolicy.go` (`PolicyPerformanceHint`).
_Avoid_: nothing known

**Untracked policy**:
Policy evaluated without connection tracking, in the `*tables` raw table or in BPF-mode XDP. The model field is `DoNotTrack`.
Code: `libcalico-go/lib/backend/model/policy.go` (`DoNotTrack`), `felix/bpf/polprog/pol_prog_builder.go` (`XDP`).
_Avoid_: stateless policy

**Pre-DNAT policy** and **forward policy**:
Host endpoint policy applied before DNAT, and host endpoint policy applied to forwarded traffic.
Code: `felix/rules/rule_defs.go` (`HostEndpointToFilterChains`), `felix/bpf/polprog/pol_prog_builder.go` (`HostPreDnatTiers`, `HostForwardTiers`).

**Failsafe port**:
A port Felix always allows so that a broken cluster stays reachable.
Code: `felix/bpf/failsafes/failsafes.go`.
_Avoid_: bare "failsafe"

**Tier-scoped resource**:
The RBAC pseudo-resource `tier.<resource>`, for example `tier.networkpolicies`, that rules grant to give access to policy within a tier.
Code: `apiserver/pkg/registry/projectcalico/authorizer/authorizer.go` (`NewTierAuthorizer`).
_Avoid_: tiered policy resource

**Tier wildcard**:
The RBAC resource name `<tier>.*`, which grants access to every policy in one tier.
Code: `apiserver/pkg/registry/projectcalico/authorizer/authorizer.go` (`NewTierAuthorizer`).
_Avoid_: nothing known

**Tier authorizer**:
The check run before a tiered policy operation: the user needs GET on the tier, and access to the tier-scoped resource for the policy's name or for the tier wildcard. The Calico apiserver and the admission webhooks' tiered RBAC hook both run it.
Code: `apiserver/pkg/registry/projectcalico/authorizer/authorizer.go` (`TierAuthorizer`), `webhooks/pkg/rbac/rbac.go` (`tieredRBACHook`).
_Avoid_: authorizer webhook

**Policy Sync API**:
Felix's `felix.PolicySync` gRPC service, with a `Sync` stream of policy updates to the client and a `Report` call carrying statistics back. It serves per-workload policy to per-pod clients such as Dikastes over a per-pod socket; Felix hosts the Policy Sync server and Dikastes runs the policy sync client.
Code: `felix/proto/felixbackend.proto` (`PolicySync`), `felix/policysync/server.go` (`Server`).
_Avoid_: nodeagent, nodeagent API

**Subscription type**:
The Policy Sync mode a client asks for: `per-pod-policies`, which streams the policy for one endpoint (the sidecar case), or `per-host-policies`, which streams all of the host's endpoints.
Code: `app-policy/syncher/syncserver.go` (`WithSubscriptionType`, `DefaultSubscriptionType`).
_Avoid_: sidecar mode

**Workload credentials**:
Per-pod `{Uid, Workload, Namespace, ServiceAccount}` that pod2daemon writes and Felix's binder attaches to gRPC peers.
Code: `pod2daemon/binder/auth.go` (`Credentials`).
_Avoid_: nodeagent (except in the frozen socket path), udsuspver

### IPAM

The IPAM library, calico-ipam and IPAM GC internals are in [design/ipam/GLOSSARY.md](design/ipam/GLOSSARY.md). The calico network plugin's terms are in [cni-plugin/GLOSSARY.md](cni-plugin/GLOSSARY.md).

**IP pool**:
A v3 IPPool: a CIDR Calico may allocate from, with a block size, allowed uses, selectors and encapsulation. The operator's `Installation.spec.calicoNetwork.ipPools[]` entry is an [`IPPool` (Installation)](operator/GLOSSARY.md#ippool-installation).
Code: `libcalico-go/lib/ipam/pool_qualification.go` (`qualifyPools`), `operator/api/v1/installation_types.go` (`IPPool`).
_Avoid_: subnet, address pool

**IPAM block**:
A fixed-size CIDR of a pool holding per-ordinal allocations. It is the unit of CAS writes and of route aggregation, and is affine to at most one host or virtual owner.
Code: `libcalico-go/lib/backend/model/block.go` (`AllocationBlock`).
_Avoid_: chunk, subnet, bare "block"

**Pool containing the block**:
The IP pool whose CIDR contains the block's CIDR. The accounting tracker attributes the block's counts to it, and picks the best-ranked pool when more than one contains the block.
Code: `libcalico-go/lib/ipam/accounting/pool.go` (`poolFor`).
_Avoid_: the pool that claims the block, the pool that owns the block

**Block affinity**:
A host's or virtual owner's claim on a block, in state `pending`, `confirmed` or `pendingDeletion`.
Code: `libcalico-go/lib/backend/model/block_affinity.go` (`BlockAffinityState`), `api/pkg/apis/projectcalico/v3/blockaffinity.go` (`BlockAffinitySpec`).
_Avoid_: block ownership, block lease

**Affinity to a missing node**:
A block affinity whose node is not in the node list the accounting tracker was given. The tracker counts these blocks separately as `StaleAffinity`.
Code: `libcalico-go/lib/ipam/accounting/counts.go` (`StaleAffinity`), `libcalico-go/lib/ipam/accounting/tracker.go` (`AddNodes`).
_Avoid_: bare "stale affinity" (that is the unconfirmed-affinity error)

**Affinity type**:
Whether a block affinity belongs to a `host` or is `virtual`. The LoadBalancer controller owns the virtual ones.
Code: `libcalico-go/lib/ipam/ipam_types.go` (`AffinityType`).
_Avoid_: virtual on its own (the IPAM GC also uses it for stopped VMs)

**Strict affinity**:
The IPAMConfiguration setting that forbids borrowing, so a host allocates only from blocks affine to it. Windows requires it, and the operator will not proceed without it.
Code: `libcalico-go/lib/ipam/ipam_types.go` (`IPAMConfig`, `StrictAffinity`), `operator/pkg/controller/installation/windows_controller.go`.
_Avoid_: strict mode (other settings use that word)

**Borrowing**:
Allocating from a block affine to another node, or from an unaffine block.
Code: `libcalico-go/lib/ipam/accounting/allocation.go` (`IsBorrowed`).
_Avoid_: cross-node allocation, stealing

**Lent addresses**:
The addresses in a block affine to one host that a different host has allocated. They are the same addresses the other host has borrowed, seen from the lending side.
Code: `libcalico-go/lib/ipam/accounting/allocation.go` (`IsBorrowed`), `libcalico-go/lib/ipam/accounting/counts.go` (`BorrowedByNode`).
_Avoid_: bare "borrowed" for the lending side, leased addresses, stolen addresses

**Handle**:
An IPAM identifier grouping one owner's addresses so they release together. Forms are the sandbox handle, the VM handle and the legacy workload handle.
Code: `libcalico-go/lib/backend/model/ipam_handle.go` (`IPAMHandle`).
_Avoid_: allocation ID, owner

**Sandbox handle**:
The handle of the form `<network>.<container-id>` under which calico-ipam allocates one pod sandbox's addresses. A pod has several sandboxes over its life.
Code: `libcalico-go/lib/ipam/pod_handle.go` (`PodHandleID`), `cni-plugin/pkg/ipamplugin/ipam_plugin.go`.
_Avoid_: pod handle, container ID, container-ID handle

**Legacy workload handle**:
The handle of the form `<namespace>.<pod>` that earlier Calico versions allocated under. DEL still releases it alongside the sandbox handle.
Code: `libcalico-go/lib/ipam/pod_handle.go` (`ParsePodHandleIDAnyNetwork`), `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`releaseHandle`).
_Avoid_: v2 handle, workload ID, workload-ID handle, v2.x handle, pre-v3 handle

**Allocation**:
One assigned address in a block: its ordinal together with the attributes IPAM recorded for it.
Code: `libcalico-go/lib/ipam/accounting/allocation.go` (`Allocation`), `libcalico-go/lib/backend/model/block.go` (`AllocationBlock`).
_Avoid_: lease, claim; bare "allocation" for the IPAM GC's `allocation` struct (say "tracked allocation")

**Allocation type attribute**:
The `type` attribute (`ipipTunnelAddress`, `vxlanTunnelAddress`, `wireguardTunnelAddress`, LoadBalancer) that classifies non-pod allocations.
Code: `libcalico-go/lib/backend/model/block.go` (`IPAMBlockAttributeType`).
_Avoid_: allocation type, bare allocation (it means several things)

**Intended use**:
The use a request asks for (Workload, Tunnel or LoadBalancer), checked against each pool's `allowedUses`.
Code: `libcalico-go/lib/ipam/ipam_types.go` (`IntendedUse`).
_Avoid_: allowed uses (that is the pool's side of the check)

**IP reservation**:
A resource listing addresses inside pools that are never allocated.
Code: `libcalico-go/lib/ipam/accounting/reserved.go` (`NumReservedIPsInCIDR`).
_Avoid_: exclusion, "Windows-reserved"

**IPAMConfiguration**:
The cluster IPAM singleton: StrictAffinity, MaxBlocksPerHost, AutoAllocateBlocks, KubeVirtVMAddressPersistence and IPCooldownSeconds. Its internal storage kind is `IPAMConfig`.
Code: `libcalico-go/lib/ipam/ipam_types.go` (`IPAMConfig`), `api/pkg/apis/projectcalico/v3/ipamconfig.go` (`KindIPAMConfiguration`).
_Avoid_: bare "IPAMConfig"

**Cooldown**:
The period after release and before deallocation in which an address stays in `Allocations` with `ReleasedAt` set. A released address is "in cooldown", then "cooled down". Cooling addresses count inside in-use totals and are reported separately.
Code: `libcalico-go/lib/ipam/ipam_block.go` (`garbageCollect`).
_Avoid_: pending release, quarantine, cold

**Leak**:
An allocation whose owner no longer uses it. A candidate leak has its grace timer running. A confirmed leak has outlived the grace period or has an owner on a deleted node.
Code: `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`markConfirmedLeak`).
_Avoid_: orphan, stale allocation, dangling IP

**`Unreferenced`**:
The accounting predicate that an allocation has no referrer, before any grace period.
Code: `libcalico-go/lib/ipam/accounting/references.go` (`Unreferenced`).
_Avoid_: leak

**IPAM GC controller**:
The kube-controllers `IPAMController`, a sub-controller of the node controller, which frees leaked allocations, empty blocks and the IPAM state of deleted nodes. "The IPAM GC code" or "IPAM GC" names its implementation, where GC means garbage collection.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`IPAMController`).
_Avoid_: the GC (several GCs exist), IPAM garbage collector, GC controller, ipam controller, bare "GC"

**Accounting tracker**:
The incremental per-pool and per-block counts shared by the IP pool controller, the IPAM GC and `calicoctl ipam check`.
Code: `libcalico-go/lib/ipam/accounting/tracker.go` (`Tracker`).
_Avoid_: IPAM cache

### Routing and encapsulation

BIRD configuration and the confd templates are in [confd/GLOSSARY.md](confd/GLOSSARY.md). calico-node startup, autodetection and the networking backend are in [node/GLOSSARY.md](node/GLOSSARY.md). Felix's route tables and routing drivers are in [felix/GLOSSARY.md](felix/GLOSSARY.md).

**Overlay**:
A pool configured so that workload traffic crossing hosts is encapsulated (IPIP or VXLAN).
Code: `felix/calc/encapsulation_resolver.go` (`EncapsulationResolver`).
_Avoid_: tunnel mode; calling WireGuard an overlay

**Pool encapsulation mode** (pool encap mode):
How a pool encapsulates traffic between hosts: IPIP, VXLAN or not at all, each with an Always, CrossSubnet or Never setting.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`poolUsesIPIP`), `felix/calc/vxlan_resolver.go` (`VXLANResolver`).
_Avoid_: pool encapsulation class

**IPIP pool**:
A pool with `ipipMode` Always or CrossSubnet, using IP-in-IP encapsulation.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`poolUsesIPIP`).
_Avoid_: IP-in-IP, ipip tunnel

**VXLAN**:
The UDP encapsulation available to a pool.
Code: `felix/calc/vxlan_resolver.go` (`VXLANResolver`).
_Avoid_: vxlan tunnel

**CrossSubnet**:
The encapsulation mode that encapsulates only when the next hop is outside the node's subnet.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`poolUsesIPIP`).
_Avoid_: cross subnet

**No-encap pool**:
A pool with `ipipMode` and `vxlanMode` both Never. Felix calls the derived state `NoEncapNeeded`; the proto field `no_encap_enabled` is frozen.
Code: `felix/config/config_params.go` (`NoEncapNeeded`), `confd/pkg/backends/calico/bgp_processor.go` (`clusterRoutePolicy`).
_Avoid_: unencapsulated pool, noEncap

**WireGuard**:
The encryption Calico can apply to host-to-host traffic, chosen independently of encapsulation.
Code: `felix/wireguard/wireguard.go` (`Wireguard`).
_Avoid_: encrypted overlay

**BGP**:
The routing protocol BIRD speaks to distribute workload routes, configured by confd.
Code: `node/filesystem/etc/calico/confd/templates/bird.cfg.template`.
_Avoid_: BIRD (that is the daemon, not the protocol)

**Node-to-node mesh**:
The default BGP topology, in which every non-route-reflector node peers with every other.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`processMeshPeers`).
_Avoid_: full mesh

**Route reflector**:
A node with `routeReflectorClusterID` set, or an external router, that other nodes peer with instead of meshing.
Code: `libcalico-go/lib/apis/internalapi/node.go` (`RouteReflectorClusterID`).
_Avoid_: hub

**Cluster route**:
The route a node needs to reach a workload on another node, usually to that node's block.
Code: `design/cluster-route-programming/DESIGN.md`.
_Avoid_: remote route, pod route

**Cluster-route owner**:
The component, BIRD or Felix, that writes the cluster routes for one pool encapsulation mode. The `programClusterRoutes` fields in BGPConfiguration and FelixConfiguration set it, and they must be complementary.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`clusterRoutePolicy`, `programsPool`), `design/cluster-route-programming/DESIGN.md`.
_Avoid_: block owner, route owner

**programClusterRoutes**:
The BGPConfiguration and FelixConfiguration field pair naming which pool encapsulation modes BIRD and Felix each program. The operator's `clusterRoutingMode` sets both.
Code: `api/pkg/apis/projectcalico/v3/bgpconfig.go` (`ProgramClusterRoutes`), `operator/pkg/controller/installation/bgpconfig.go`.
_Avoid_: clusterRoutingMode (that is the operator's setting, which sets both), routing mode

**Blackhole block route**:
A route to a local IPAM block with a `blackhole` target, so that unknown addresses in the block drop. Felix programs it through `routeManager`, and BIRD's static protocol exports it, which gives BIRD a route to advertise for the block even when no workload route exists inside it.
Code: `felix/dataplane/linux/route_mgr.go` (`localIPAMBlocks`), `node/filesystem/etc/calico/confd/templates/bird_aggr.cfg.template` (`static_template`).
_Avoid_: IPAM-block drop route, bare "static route" (several things are called that)

**Route protocol**:
The kernel route's `proto` label. BIRD uses 12 (`RTPROT_BIRD`). Felix uses `DeviceRouteProtocol`, and substitutes the Calico route proto, 80, when that setting has its default of 3.
Code: `felix/dataplane/linux/dataplanedefs/dataplane_defs.go` (`DefaultRouteProto`), `felix/dataplane/linux/route_mgr.go` (`calculateRouteProtocol`), `felix/config/config_params.go` (`DeviceRouteProtocol`).
_Avoid_: routing protocol (that is BGP), route source (that is a different setting)

**Route priority**:
How a route ranks against others for the same prefix. It appears as Felix's route priority, the kernel metric (lower wins), BGP local preference (higher wins), and BIRD's separate `preference` attribute. Felix gives ordinary workload routes a normal route priority (default 1024) and a live-migrating workload's current home the lower metric of an elevated route (default 512), and both values must match across BGPConfiguration and FelixConfiguration.
Code: `api/pkg/apis/projectcalico/v3/bgpconfig.go` (`IPv4NormalRoutePriority`), `felix/config/config_params.go` (`IPv4NormalRoutePriority`), `confd/pkg/backends/calico/bgp_processor.go` (`buildExportFilter`).
_Avoid_: bare "preference", bare "priority" without saying which of the four

**Elevated route**:
The route Felix programs for a live-migrating workload at the elevated route priority (512 by default, against 1024 for a normal workload route), so it takes precedence while the migration converges.
Code: `felix/config/config_params.go` (`IPv4ElevatedRoutePriority`), `felix/dataplane/linux/endpoint_mgr.go` (`elevatedRoutePriority`).
_Avoid_: priority route

**Route source**:
Felix's and confd's `RouteSource` setting: routes come from WEP IPs or from IPAM blocks.
Code: `felix/config/config_params.go` (`RouteSource`).
_Avoid_: route origin (that is `LearnedFrom` in CalicoNodeStatus), route protocol (that is the kernel label)

**Service advertisement**:
Advertising Service cluster, external and LoadBalancer IPs over BGP, from CIDRs in BGPConfiguration.
Code: `confd/pkg/backends/calico/routes.go` (`advertiseThisService`).
_Avoid_: static route (the BIRD and confd word for several different routes)

**BGP syncer**:
The datastore syncer behind the `bgp` syncer type, which feeds confd the IPPool, BGPConfiguration, Node, BGPPeer and BGPFilter resources and this node's block affinities.
Code: `libcalico-go/lib/backend/syncersv1/bgpsyncer/bgpsyncer.go` (`New`).
_Avoid_: bare syncer (name the syncer type)

### Dataplane

Felix's calculation graph, its dataplane managers, `*tables` internals and the BPF programs are in [felix/GLOSSARY.md](felix/GLOSSARY.md). That file also defines the [Dataplane driver](felix/GLOSSARY.md#dataplane-driver), the [Reconciling driver](felix/GLOSSARY.md#reconciling-driver) and the [In-sync gate](felix/GLOSSARY.md#in-sync-gate).

**Dataplane**:
The kernel-level state Felix maintains on a host. Modes are iptables, nftables and eBPF on Linux, plus Windows HNS and an external driver.
Code: `felix/dataplane/driver.go` (`StartDataplaneDriver`), `operator/api/v1/installation_types.go` (`LinuxDataplaneOption`).
_Avoid_: data plane, dataplane backend

**Dataplane mode**:
Which dataplane a Felix runs, resolved from config (`BPFEnabled`, and `NFTablesMode` resolved to `NFTablesEnabled`).
Code: `felix/DESIGN.md`.
_Avoid_: backend

**Dataplane API**:
The `ToDataplane` and `FromDataplane` protobuf stream between Felix's calculation graph and a dataplane driver, including an external one.
Code: `felix/proto/felixbackend.proto` (`ToDataplane`).
_Avoid_: felixbackend (that is the proto file name), Policy Sync API (a different stream)

**`*tables`**:
iptables or nftables, the Linux dataplanes that render rules rather than BPF programs.
Code: `felix/design/bpf-overview.md`.
_Avoid_: legacy dataplane, netfilter dataplane

**iptables backend**:
Which iptables binary family Felix uses, legacy or nft (`IptablesBackend`).
Code: `felix/config/config_params.go` (`IptablesBackend`).
_Avoid_: "nftables backend", for nftables mode

**Dataplane resync**:
Felix's full reconciliation against kernel state when its cached view may be stale.
Code: `felix/routetable/interface.go` (`OnIfaceStateChanged`).
_Avoid_: refresh, full sync, bare "resync"

**Restart exit code**:
The exit code 129, which asks a supervisor (runit, `calico-felix-wrapper` or `cmdwrapper.WrapSelf`) to relaunch a component.
Code: `pkg/cmdwrapper/cmdwrapper.go` (`RestartReturnCode`).
_Avoid_: config-change restart (that is the reason for the restart, not the code)

**Config-change restart**:
A component exiting with the restart exit code to apply a change it cannot hot-reload, then relying on its init system or restart wrapper to start it again. Felix exits when a parameter it cannot hot-reload, the encapsulation state or datastore readiness changes, and kube-controllers restarts the whole process when its running config changes, never one controller alone.
Code: `felix/daemon/daemon.go` (`configChangedRC`, `handledConfigChanges`), `kube-controllers/pkg/kubecontrollers/run.go` (`controllerControl`), `kube-controllers/pkg/kubecontrollers/command.go` (`WrapSelf`).
_Avoid_: reload, config restart, restart-to-apply

**Health aggregator** and **health reporter**:
The shared liveness and readiness registry, and its named, optionally timed reporters, served on `/liveness` and `/readiness`.
Code: `libcalico-go/lib/health/health.go` (`HealthAggregator`, `RegisterReporter`).
_Avoid_: bare "reporter", bare "aggregator"

### Flow logs

Goldmane's bucket ring, emission windows and replay are in [goldmane/GLOSSARY.md](goldmane/GLOSSARY.md), which also defines the [Goldmane engine](goldmane/GLOSSARY.md#goldmane-engine). The Whisker backend's visibility filter is in [whisker-backend/GLOSSARY.md](whisker-backend/GLOSSARY.md). The BPF [Policy-verdict event](felix/GLOSSARY.md#policy-verdict-event) is in [felix/GLOSSARY.md](felix/GLOSSARY.md).

**Flow log**:
Felix's record of traffic for one flow key over one flush interval, produced by `felix/collector` at one of its aggregation levels (0 to 3).
Code: `felix/collector/flowlog/types.go` (`FlowLog`), `felix/collector/flowlog/aggregator.go`.
_Avoid_: connection log, bare "flow"

**Goldmane Flow**:
Statistics for the connections that share one flow key over a start-to-end window, aggregated across time, reporting nodes or both. It is the `Flow` message that Goldmane stores and serves, and it differs from Felix's flow log.
Code: `goldmane/proto/api.proto` (`Flow`).
_Avoid_: aggregated flow, bare "flow"

**Flow key**:
The identity of a Goldmane Flow: source and destination name, namespace and endpoint type, destination port, service, protocol, reporter, action and policy trace. Source and destination IP addresses never enter it.
Code: `goldmane/proto/api.proto` (`FlowKey`), `goldmane/pkg/types/flow.go` (`FlowKey`).
_Avoid_: FlowMeta (that is Felix's flow log key), flow meta

**Reporter (src/dst)**:
Which end of the connection measured the flow.
Code: `goldmane/proto/api.proto` (`Reporter`).
_Avoid_: bare "reporter"

**Flow endpoint type**:
`WorkloadEndpoint`, `HostEndpoint`, `NetworkSet` or `Network` (named `pub` or `pvt`) for each side of a flow.
Code: `goldmane/proto/api.proto` (`EndpointType`).
_Avoid_: bare endpoint (WorkloadEndpoint, HostEndpoint and others are all called that)

**Policy trace** and **policy hit**:
The ordered list of policy rules that acted on a flow (an enforced list and a pending list), and one entry in it.
Code: `goldmane/proto/api.proto` (`PolicyTrace`).

**End-of-tier hit**:
A policy hit of kind `EndOfTier`, whose `trigger` names the first policy that selected the flow in that tier.
Code: `goldmane/proto/api.proto` (`PolicyHit`, `EndOfTier`).
_Avoid_: implicit deny (a hit of kind `EndOfTier` is not a rule), default deny (it is not a default-deny policy)

**Filter hints**:
The distinct values of one flow field, such as destination names, that match a filter, which clients use for autocomplete. Whisker-backend derives them only from flows the [visibility filter](whisker-backend/GLOSSARY.md#visibility-filter) admits.
Code: `goldmane/proto/api.proto` (`FilterHints`), `whisker-backend/pkg/apis/v1/flows.go` (`FlowsFilterHintsPath`).
_Avoid_: filters

**Query filter**:
The `Filter` message that narrows a `List`, `Stream` or `FilterHints` request to Goldmane, which Whisker-backend builds from the `Filters` in a flows request. It is not a visibility filter.
Code: `goldmane/proto/api.proto` (`Filter`), `whisker-backend/pkg/apis/v1/flows.go` (`Filters`).
_Avoid_: visibility filter (that is whisker-backend's), bare filter (it means several things)

**FlowCollector API**:
`goldmane.FlowCollector/Connect`, the bidirectional stream Felix reports flows on, over TCP to Goldmane or over the local socket `/var/run/calico/flows/flows.sock`.
Code: `goldmane/proto/api.proto` (`FlowCollector`), `felix/collector/local/server.go` (`SocketDir`).
_Avoid_: Policy Sync API (that is a different stream)

**Flow log dispatcher**:
A Felix collector output (`GoldmaneReporter` or `LocalSocketReporter`) that sends flow logs to one destination.
Code: `felix/collector/goldmane/client.go` (`GoldmaneReporter`), `felix/collector/dpstatshelper.go`.
_Avoid_: reporter, for the output (that is the src/dst field)

### Components

Each component's building blocks are in its own glossary: [felix](felix/GLOSSARY.md), [typha](typha/GLOSSARY.md), [confd](confd/GLOSSARY.md), [node](node/GLOSSARY.md), [kube-controllers](kube-controllers/GLOSSARY.md), [operator](operator/GLOSSARY.md), [cni-plugin](cni-plugin/GLOSSARY.md), [apiserver](apiserver/GLOSSARY.md), [calicoctl](calicoctl/GLOSSARY.md), [goldmane](goldmane/GLOSSARY.md), [whisker-backend](whisker-backend/GLOSSARY.md), [guardian](guardian/GLOSSARY.md) and [app-policy](app-policy/GLOSSARY.md). The [Guardian](guardian/GLOSSARY.md#guardian) agent is defined in the guardian glossary.

**Felix**:
The per-host agent that resolves policy and programs the dataplane.
Code: `felix/daemon/daemon.go` (`Run`).
_Avoid_: the agent

**Typha**:
The fan-out proxy between the datastore and the Felix, confd and calico-node instances, so that datastore watch load does not grow with node count.
Code: `typha/pkg/daemon/daemon.go` (`syncerPipeline`).
_Avoid_: the proxy, cache

**confd**:
The per-host daemon that renders BIRD configuration from BGP syncer updates.
Code: `confd/pkg/backends/calico/client.go` (`client`).
_Avoid_: config daemon

**BIRD**:
The forked BGP daemon in the node image that distributes and installs routes.
Code: `node/filesystem/etc/service/available/bird/run`.
_Avoid_: the router

**calico-node**:
The per-host pod and image running Felix, confd, BIRD and node-services under runit, plus the startup sequence.
Code: `node/filesystem/etc/rc.local`.
_Avoid_: node agent, the node

**Operator**:
The tigera-operator deployment that installs and reconciles Calico from an Installation.
Code: `operator/pkg/daemon/daemon.go` (`Run`).
_Avoid_: the installer

**kube-controllers**:
The cluster-wide controllers for Calico resource lifecycle (IP pools, tiers), Kubernetes mirroring, the IPAM GC, LoadBalancer IPAM and migrations.
Code: `kube-controllers/pkg/kubecontrollers/run.go` (`controllerControl`).
_Avoid_: the controllers

**CNI plugin**:
The binary kubelet invokes to attach a pod to the Calico network. It runs as the `calico` network plugin and the `calico-ipam` IPAM plugin.
Code: `cni-plugin/cmd/calico/calico.go` (`main`).
_Avoid_: the CNI

**Calico apiserver**:
The aggregated API server in `apiserver/` that serves the aggregated v3 API through the Kubernetes aggregation layer when `crd.projectcalico.org/v1` CRDs back the datastore. It is not kube-apiserver.
Code: `apiserver/pkg/apiserver/apiserver.go` (`ProjectCalicoServer`).
_Avoid_: the aggregator, bare "apiserver" (that is kube-apiserver), Tigera API server

**Admission webhooks**:
The Kubernetes admission webhooks served by `calico component webhooks`. They give tier RBAC and ClusterInformation write protection to clusters that serve `projectcalico.org/v3` from CRDs, where no Calico apiserver runs, and they can authorize only admission requests, so they never see GET, LIST or WATCH.
Code: `webhooks/pkg/webhook/command.go` (`registerHooks`).
_Avoid_: bare "webhook", the authorizer

**calicoctl**:
The CLI that reads and writes Calico resources directly through libcalico-go, bypassing apiserver tier RBAC.
Code: `calicoctl/calicoctl/commands/command.go`.
_Avoid_: calico ctl, kubectl-calico (an invocation name for the same binary), Calico CLI

**Goldmane**:
The cluster-wide flow aggregation and query service that Felix reports flows to.
Code: `goldmane/pkg/goldmane/goldmane.go` (`Goldmane`).
_Avoid_: the aggregator

**Whisker**:
The flow UI, served by nginx, which proxies `/whisker-backend/` to whisker-backend.
Code: `whisker/docker-image/default.conf`.
_Avoid_: the UI, the dashboard

**whisker-backend**:
The HTTPS server that gives Whisker flows and filter hints from Goldmane.
Code: `whisker-backend/cmd/whiskerbackend/app.go` (`NewHTTPServer`).
_Avoid_: bare "backend"

**Dikastes**:
The program built from `app-policy/`, which Envoy calls through the `ext_authz` filter. It enforces application-layer policy by deciding each request against the policy Felix streams to it.
Code: `app-policy/pkg/dikastes/dikastes.go` (`RunServer`).
_Avoid_: ALP server, the sidecar, L7 proxy

**pod2daemon**:
The flexvolume and CSI driver that gives each pod a directory in which Felix's binder creates its per-pod Policy Sync socket.
Code: `pod2daemon/pkg/flexvol/flexvol.go`.
_Avoid_: volume plugin

**key-cert-provisioner**:
The init container that creates a key and CSR, submits a Kubernetes CSR, and writes the signed certificate.
Code: `key-cert-provisioner/pkg/keycert/run.go` (`Run`).
_Avoid_: operator CSR signer (that is the other side of the CSR)

**Combined binary**:
The `calico/calico` image and binary that runs most components as `calico component <name>`, and the CNI plugin by `argv[0]`.
Code: `cmd/calico/component.go` (`newComponentCommand`), `cmd/calico/main.go` (`dispatch`).
_Avoid_: "component", for the subcommand alone

## Words that need a qualifier

Each word below means several things in the code. Use the phrase in the last column instead of the bare word. Where the first column says "In Felix" or similar, the rule holds only there.

| Word | Meanings (anchor) | Say |
|---|---|---|
| component | A separately running program; a component render implementation (`operator/pkg/render/component.go` (`Component`)); an image component (`operator/pkg/components/references.go` (`Component`)); a status area with its own TigeraStatus (`operator/DESIGN.md`); the Installation `ComponentName` enum (`operator/api/v1/installation_types.go`); image keys (`operator/pkg/render/component.go` (`ComponentNameNode`)); the `app.kubernetes.io/component` label (`operator/pkg/controller/utils/component.go`); a `calico component <name>` subcommand (`cmd/calico/component.go` (`newComponentCommand`)); a workload found in a manifest install (`operator/pkg/controller/migration/convert/components.go`); a UI component, such as Whisker, served through the Calico Ingress Gateway (`operator/pkg/uigateway/uigateway.go` (`Config`)); the `ComponentAvailable` and `ComponentDegraded` status conditions (`operator/api/v1/tigerastatus_types.go`) | Bare "component" means a running program only. Otherwise: component render implementation, image component, status area, image key, workload name, component subcommand, UI component. |
| migration | v1-to-v3 CRD migration (`kube-controllers/pkg/controllers/migration/controller.go`); etcd-to-KDD migration (`calicoctl/calicoctl/commands/datastore_command.go`); policy-name migration (`kube-controllers/pkg/controllers/networkpolicy/policy_name_migrator.go`); Flannel migration (`kube-controllers/pkg/controllers/flannelmigration/migration_controller.go`); operator namespace migration (`operator/pkg/controller/migration/namespace_migration.go`); install conversion (`operator/pkg/controller/migration/converter.go`); field-ownership migration (`operator/pkg/controller/managedfields/migrate.go`); live migration (`felix/calc/live_migration_calculator.go`) | Always prefix the kind. "Live migration" is the VM move. |
| v1 | The v1 model (`libcalico-go/lib/backend/model/`); the legacy v1 northbound API (`libcalico-go/lib/apis/v1/README.md`); `crd.projectcalico.org/v1` CRDs (`libcalico-go/lib/backend/k8s/resources/apigroups.go`); `ClientV1` resource clients (`libcalico-go/lib/backend/k8s/resources/ipam_affinity_v1.go`); a policy's stored name before policy-name migration (`kube-controllers/pkg/controllers/networkpolicy/policymigrate.go`); `migration.projectcalico.org/v1` (`kube-controllers/pkg/apis/migration/v1/types.go`); confd's `/calico/bgp/v1/` key space (`confd/pkg/backends/calico/client.go`) | Never bare: "v1 model", "legacy v1 API", "crd.projectcalico.org/v1 CRDs", "confd key space". |
| v3 | The v3 API (`api/pkg/apis/projectcalico/v3/`); `projectcalico.org/v3` CRDs as storage (`libcalico-go/lib/backend/k8s/discovery.go`); the aggregated v3 API (`apiserver/pkg/apiserver/apiserver.go`) | "v3 API" for types; "projectcalico.org/v3 CRDs" for storage; "aggregated v3 API" for what the Calico apiserver serves. |
| v2 | A stale name for v3 in update processors (`libcalico-go/lib/backend/syncersv1/updateprocessors/conflictresolvingcacheproc.go`); the "v2.x workload ID handle" (`cni-plugin/pkg/ipamplugin/ipam_plugin.go`); the `/calico/ipam/v2/` key (`confd/pkg/backends/calico/client.go`) | Read it as v3 in update processors; say "legacy workload handle" for the handle. |
| manager | Felix `Manager` interface (`felix/dataplane/linux/int_dataplane.go` (`Manager`)); Felix drivers named Manager (`felix/linkaddrs/link_addrs.go`, `felix/routetable/conntrack_owner_tracker.go`, `felix/rules/epmark.go`); the unregistered `routeManager` helper (`felix/dataplane/linux/route_mgr.go`); BPF `failsafes.Manager` (`felix/bpf/failsafes/failsafes.go`); operator status, certificate and field managers (`operator/pkg/controller/status/status.go`, `operator/pkg/controller/certificatemanager/certificatemanager.go`, `operator/pkg/controller/managedfields/fieldmanager.go`); the controller-runtime Manager (`operator/internal/controller/controllers.go`) | In Felix, "manager" means a `Manager` implementer only; call the rest a reconciling driver or a helper. Elsewhere always qualify (status manager). |
| driver | Felix `DataplaneDriver` (`felix/dataplane/driver_defs.go`); Felix's reconciling layer (`felix/DESIGN.md`); an external driver process (`felix/dataplane/external/ext_dataplane.go`); KDD; pod2daemon's flexvol and CSI drivers (`pod2daemon/csidriver/driver/driver.go`); the "legacy ipsets driver" (`felix/design/dataplane.md`) | "Dataplane driver" for `DataplaneDriver`; "reconciling driver" or the package name for the lower layer; "volume driver" for pod2daemon. |
| legacy | `*tables` as "legacy netfilter dataplane" (`felix/design/dataplane.md`); the iptables-legacy backend (`felix/config/config_params.go` (`IptablesBackend`)); legacy XDP; the ipset-command driver; `LegacyPolicyKey` (`typha/pkg/syncproto/sync_proto.go`); `felix/bpf/legacy` cleanup; the legacy workload handle | Reserve for the iptables-legacy backend. Otherwise say "`*tables`", "iptables-mode XDP", "ipset-command driver", "legacy workload handle". |
| ingress / egress | Policy direction (`felix/bpf-gpl/cali_bpf.h`); TC hook direction relative to the host (`felix/bpf/hook/load.go`); "host-ingress" (`felix/design/bpf-overview.md`); `InboundRules` and `OutboundRules` in the v1 model (`libcalico-go/lib/backend/model/policy.go`); Kubernetes Ingress and Gateway | "Ingress policy" for direction. "To-host (TC ingress) hook" and "from-host (TC egress) hook" for the kernel side. Never bare "ingress" for a WEP. |
| resync / reconcile / refresh / full sync | Datastore resync (`libcalico-go/lib/backend/api/api.go` (`ResyncInProgress`)); dataplane resync (`felix/proto/felixbackend.proto`, `felix/routetable/interface.go`); refresh timers (`felix/dataplane/linux/int_dataplane.go`); the IP-set rolling resync (`felix/ipsets/resync_queue.go`); the kube-controllers ResourceCache periodic reconciler (`kube-controllers/pkg/cache/cache.go`); one workqueue reconcile (`kube-controllers/pkg/controllers/ippool/pool_controller.go`); the IPAM GC full sync (`kube-controllers/pkg/controllers/node/ipam.go`); confd's "full sync" for data-source readiness (`confd/pkg/backends/calico/client.go`); informer resync | "Datastore resync" or "dataplane resync". "Refresh timer" for the trigger. "Periodic reconciler" for ResourceCache. "Reconcile" for one workqueue pass. "Full sync" and "incremental sync" only for the IPAM GC. "Full pass" for kicking one kube-controllers pass. |
| apiserver | Calico apiserver (`apiserver/pkg/apiserver/apiserver.go`); kube-apiserver (`kube-controllers/pkg/kubecontrollers/run.go`); the operator APIServer resource (`operator/api/v1/apiserver_types.go`) | "Calico apiserver", "kube-apiserver", "APIServer CR". |
| allocation | A block ordinal slot (`libcalico-go/lib/backend/model/block.go`); `model.Allocation{Addr,Host}`; `accounting.Allocation` (`libcalico-go/lib/ipam/accounting/allocation.go`); the IPAM GC's `allocation` struct (`kube-controllers/pkg/controllers/node/ipam_allocation.go`); a Typha connection's share | "Allocation" is one assigned ordinal plus attribute. "Tracked allocation" for the GC struct. |
| override | Operator workload overrides (`operator/api/v1/installation_types.go`); the overlay merge `OverrideInstallationSpec` (`operator/pkg/controller/utils/merge.go`); image override keys (`operator/pkg/render/component.go`); `ConflictOverride` (`operator/pkg/controller/managedfields/declaration.go`); BIRD's override preference (`confd/pkg/backends/calico/bgp_processor.go`) | "Overrides" means workload overrides. Otherwise: "overlay merge", "effective installation" (the spec plus defaults plus overlay), "image key", "Override conflict policy", "override preference". |
| static route | Service CIDRs under `/calico/staticroutes` (`confd/pkg/backends/calico/client.go`); blackhole block routes in BIRD's static protocol (`node/filesystem/etc/calico/confd/templates/bird_aggr.cfg.template`); `reachableBy` peer routes; the "Don't program static routes" reject CIDRs (`node/filesystem/etc/calico/confd/templates/bird_ipam.cfg.template`) | "Advertised service route", "blackhole block route", "peer reachability route", "kernel-reject CIDR". |
| emit / emission | Goldmane's `emissionKey`, one node's report into a bucket (`goldmane/pkg/storage/bucket.go`); Goldmane pushing to the sink (`goldmane/pkg/goldmane/goldmane.go`); BPF `event_flow_log` (`felix/bpf-gpl/events.h`); the calculation graph emitting proto messages (`felix/calc/event_sequencer.go`) | "Emit" is Goldmane-to-sink only. The calculation graph "flushes". |
| aggregator | Goldmane's engine (`goldmane/pkg/goldmane/goldmane.go`); Felix `flowlog.Aggregator` (`felix/collector/flowlog/aggregator.go`); `HealthAggregator` (`libcalico-go/lib/health/health.go`); the Kubernetes aggregation layer that serves the Calico apiserver | "Goldmane engine", "Felix flow log aggregator", "health aggregator", "kube-aggregator". |
| staged / pending | Staged policy (`api/pkg/apis/projectcalico/v3/policy_common.go`); the pending policy trace (`goldmane/proto/api.proto`, `whisker-backend/pkg/apis/v1/flows.go`); Dikastes's pending store (`app-policy/policystore/store.go`); a pending block affinity (`api/pkg/apis/projectcalico/v3/blockaffinity.go`); `EventSequencer` pending buffers (`felix/calc/event_sequencer.go`); a manager's pending state (`felix/dataplane/linux/endpoint_mgr.go`); migration phase Pending (`kube-controllers/pkg/apis/migration/v1/types.go`) | "Staged policy" for the resource; "pending policy trace"; "pending store"; "pending affinity"; "pending buffer". |
| backend | The datastore client `api.Client` (`libcalico-go/lib/backend/api/api.go`); the v1 model (`libcalico-go/lib/backend/syncersv1/updateprocessors/rules.go`); the backing API group (`libcalico-go/lib/backend/k8s/discovery.go`); the iptables backend (`felix/config/config_params.go`); "nftables backend" for the mode (`felix/design/dataplane.md`); a service's backend pod (`felix/bpf/nat/maps.go`); the networking backend (`node/filesystem/etc/rc.local`); whisker-backend; the flows backend (`whisker-backend/pkg/apis/v1/backend.go`) | "Backend client", "backing API group", "iptables backend", "service backend", "networking backend", "flows backend". |
| cache / SnapshotCache | Typha `snapcache.Cache` (`typha/pkg/snapcache/cache.go`); `syncserver.SnapshotCache` and binary snapshots (`typha/pkg/syncserver/snap_precalc.go`); the watcher cache (`libcalico-go/lib/backend/watchersyncer/watchercache.go`); update-processor caches (`libcalico-go/lib/backend/syncersv1/updateprocessors/conflictresolvingcacheproc.go`); the confd client cache; the kube-controllers ResourceCache (`kube-controllers/pkg/cache/cache.go`); Felix's lookups cache (`felix/calc/lookups_cache.go`); Goldmane's replay cache (`goldmane/pkg/internal/flowcache/timed_cache.go`) | Always qualify. In Typha, "snapshot cache" or "binary snapshot cache". |
| ValidationFilter | Typha's (`typha/pkg/calc/validation_filter.go`) and Felix's (`felix/calc/validation_filter.go`), same name and role | "`ValidationFilter` (Typha)", "`ValidationFilter` (Felix)". |
| sub-program | The BPF generic sub-program in the generic jump map (`felix/bpf/hook/map.go`); a policy sub-program, a chained slice of a policy program (`felix/bpf/jump/map.go`) | Always "generic sub-program" or "policy sub-program". |
| XDP | BPF-mode XDP running untracked host endpoint policy (`felix/bpf-gpl/xdp.c`); iptables-mode XDP acceleration through `xdpState` (`felix/dataplane/linux/xdp_state.go`) | "BPF-mode XDP" or "iptables-mode XDP". |
| conntrack | The BPF conntrack table `cali_v4_ct` (`felix/bpf-gpl/conntrack_types.h`); kernel netfilter conntrack (`felix/bpf-gpl/cali_bpf.h`); Felix's route-table conntrack cleanup (`felix/routetable/conntrack_owner_tracker.go`) | "BPF conntrack" or "kernel conntrack". |
| syncer | The datastore syncer (`libcalico-go/lib/backend/api/api.go`); Felix route syncers (`felix/routetable/interface.go`); the BPF service syncer (`felix/bpf/proxy/syncer.go`); the kube-controllers DataFeed (`kube-controllers/pkg/controllers/utils/syncer.go`); `syncIPAM` in two controllers (`kube-controllers/pkg/controllers/node/ipam.go`, `kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go`) | "Datastore syncer", "route syncer", "BPF service syncer", "DataFeed". |
| endpoint | WEP, HEP; Kubernetes Endpoints and EndpointSlices; HTTP endpoints; VTEP; the WireGuard "endpoint" (a node) (`felix/wireguard/wireguard.go`); a BPF attach point, of which one endpoint has several (`felix/bpf/tc/attach.go`); `httpmachinery` `Endpoint` (`lib/httpmachinery/pkg/apiutil/types.go`) | Name which. "WireGuard peer" for the WireGuard case. |
| node | The Calico Node; the Kubernetes Node; the host; a calculation node (`felix/design/calc-graph.md`); a trie node `IPTrieNode` (`felix/calc/iplpm.go`); Goldmane's "node", meaning a peer IP (`goldmane/pkg/server/flow_collector_service.go`); knode and cnode in the IPAM GC (`kube-controllers/pkg/controllers/node/ipam.go`) | "Node" (Calico), "node name" (the Kubernetes Node's name), "v3.Node name", "Kubernetes Node", "host", "calculation node", "trie node", "reporter address". |
| block | The IPAM block; a BPF backend-map range; a mark-bit range; the verb | "IPAM block". |
| policy | Calico policy; a BPF policy program; policy direction; `OwnershipPolicy` (`felix/routetable/route_table.go`); `clusterRoutePolicy` (`confd/pkg/backends/calico/bgp_processor.go`); Kubernetes traffic policy; policy-based routing | Name which. A bare "policy" means a Calico network policy. |
| rule | A Calico rule; a `*tables` rule; an ip rule (`felix/routerule/route_rule.go`); a BGPFilter rule; a BIRD filter statement | "Calico rule", "`*tables` rule", "ip rule", "BGPFilter rule". |
| table | A netfilter logical table (`felix/nftables/table_layer.go`); the nft root table (`felix/dataplane/linux/int_dataplane.go`); `iptables.Table` (`felix/iptables/table.go`); a routing table (`felix/routetable/route_table.go`); the BPF conntrack table; the Maglev lookup table (`felix/bpf/nat/maps.go`); a BIRD table | "Logical table", "root table", "routing table", "BPF conntrack table". |
| map | A BPF map; the jump map (programs); an nft map; a Go map; the dispatch map (`felix/rules/rule_defs.go`) | "BPF map", "jump map", "nft map". |
| flow / flow log | A connection; the Felix flow log; the Goldmane Flow; BPF policy-verdict events (`felix/bpf-gpl/events.h`); an nftables flowtable entry; flow-based VXLAN | "Flow log" is Felix's record; "Goldmane Flow" is Goldmane's; "policy-verdict event" for BPF. |
| affinity | Block affinity; `sessionAffinity` and the BPF affinity map (`felix/bpf/nat/maps.go`); the `virtual:` affinity string | "Block affinity", "session affinity". |
| claim | An IPAM block claim (`libcalico-go/lib/ipam/ipam_block_reader_writer.go`); `PoolClaim`, the pool eligibility rule (`libcalico-go/lib/ipam/pool_qualification.go` (`PoolClaim`)); calico-ipam's `claimedAfter` (`cni-plugin/pkg/ipamplugin/ipam_plugin.go`); Goldmane's emission claim (`goldmane/pkg/storage/bucket.go`) | "Block claim", "pool qualification" for the rule and "pool resolution" for name-to-CIDR, "pool containing the block", "emission claim". |
| stale affinity | `errStaleAffinity`, an unconfirmed affinity on a block another host owns (`libcalico-go/lib/ipam/ipam_errors.go`); `Counts.StaleAffinity`, an affinity to a missing node (`libcalico-go/lib/ipam/accounting/counts.go`) | "Affinity to a missing node" for the second. |
| in-sync | Datastore in-sync; dataplane in-sync (`felix/proto/felixbackend.proto`); interface-monitor in-sync (`felix/dataplane/linux/int_dataplane.go`); confd's data-source readiness (`confd/pkg/backends/calico/client.go`); Dikastes's store swap on InSync (`app-policy/policystore/store.go`) | Always say whose in-sync. "In-sync gate" for Felix's combined datastore and interface-monitor condition. |
| ready | Operator `render.Component.Ready()` (`operator/pkg/render/component.go`); TigeraStatus Ready (`operator/api/v1/tigerastatus_types.go`); the datastore ready flag; BPF interface readiness (`felix/dataplane/linux/bpf_ep_mgr.go`); health readiness | "Render precondition", "datastore ready flag", "interface readiness". |
| sandbox / container | A CNI sandbox (`cni-plugin/pkg/ipamplugin/ipam_plugin.go`); the "container" parameter, which means the sandbox (`cni-plugin/internal/pkg/utils/utils.go`) | "Sandbox". "Prior sandbox" for an earlier sandbox of the same pod, "superseded sandbox" for one the runtime gave up on. |
| handover / cutover | The IPAM sandbox handover (`cni-plugin/pkg/ipamplugin/ipam_plugin.go`); the cluster-route handover (`design/cluster-route-programming/DESIGN.md`); the operator's APIService cutover (`operator/pkg/controller/apiserver/cutover.go`); kube-controllers' APIService removal during CRD migration (`kube-controllers/pkg/controllers/migration/controller.go`) | Prefix the subject every time: "sandbox handover", "cluster-route handover", "APIService cutover", "APIService handover". |
| plane | The IP family in `ipsets.IPSets` (`felix/ipsets/ipsets.go`) and `felix/design/dataplane.md` | "IP family". |
| deferred | `DeferredCRDController` (`kube-controllers/pkg/controllers/controller/deferred.go`); kubevirt `DeferredInformers` (`libcalico-go/lib/kubevirt/state.go`); Felix `CompleteDeferredWork` (`felix/dataplane/linux/int_dataplane.go`); Goldmane `DeferredFlowBuilder` (`goldmane/pkg/storage/deferred_builder.go`) | Fine as identifiers. Qualify in prose. |
| scope | Goldmane node scope (`goldmane/pkg/server/flow_collector_service.go`); Dikastes policy scope (`app-policy/checker/check.go`); confd peer scope | Name which. |
| local | Hosted on this node (`felix/calc/calc_graph.go`); a Felix local-only config parameter (`felix/config/config_params.go`); `externalTrafficPolicy=Local`; host-local IPAM; link-local; a local workload BGP peer (`confd/pkg/backends/calico/client.go`); the local flow socket (`felix/collector/local/server.go`) | "Local endpoint", "local-only parameter", "Local traffic policy", "local workload peer". |
| mark | The skb mark (`felix/bpf-gpl/cali_bpf.h`); connmark; mark bits (`felix/dataplane/driver.go`); the endpoint mark (`felix/rules/epmark.go`); mark-and-sweep | "skb mark", "mark bits", "endpoint mark". |
| reserved | IPReservation; the Windows-reserved handle (`libcalico-go/lib/ipam/accounting/allocation.go`); accounting's `reservedClass` (`libcalico-go/lib/ipam/accounting/tracker.go`); the BPF skb-mark range | "IP reservation", "Windows-reserved addresses". |
| render | Operator manifest generation; confd template rendering; Felix `*tables` rule rendering (`felix/rules/rule_defs.go`) | Name which. |
| operator | A person running Calico; the tigera-operator | "Administrator" for the person; "the operator" for the program. |
| GC | IPAM library read-time deallocation (`libcalico-go/lib/ipam/ipam_block.go`); the IPAM GC; cold-IP GC (`kube-controllers/pkg/controllers/node/ipam.go`); the LoadBalancer controller's "garbage collection for leaked IP addresses" (`kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go`); kernel cleanup | "The IPAM GC" is the kube-controllers one. Otherwise "read-time GC" (also "write-folded deallocation"), "unclaimed LoadBalancer IPs". |
| release | Releasing an IP; a product release; BIRD withdrawing a route | Name which. |
| FV | Felix calc-graph FV, which is unit tests (`felix/calc/calc_graph_fv_test.go`); Felix FV; Goldmane FV; operator FV | Name the suite. |
| variant | The operator's product variant (`operator/api/v1/installation_types.go`); the BPF object variant `hook.AttachType` (`felix/bpf/hook/load.go`); `_notrace` and `_DEBUG` builds | "Product variant", "BPF object variant". |
| attach type | The config `BPFAttachType` TC, TCX or netkit (`felix/config/config_params.go`); the `hook.AttachType` tuple (`felix/bpf/hook/load.go`); the kernel's `expected_attach_type` (`felix/dataplane/linux/bpf_ep_mgr.go`) | "Attach mechanism" for clsact, TCX and netkit. "Object variant" for `hook.AttachType`. |
| owner / ownership | Block affinity ("node that owns the block", `design/cluster-route-programming/DESIGN.md`); the cluster-route owner; Felix's route `OwnershipPolicy` (`felix/routetable/route_table.go`); the IPAM active and alternate owner (`libcalico-go/lib/backend/model/block.go`); OwnerReferences; operator field ownership | "Affine host", "cluster-route owner", "active owner". |
| program / programmed | Writing kernel state; confd's `programmedRoutes`, meaning keys added for advertisement (`confd/pkg/backends/calico/client.go`); a BPF program; a force-programmed policy (`felix/calc/active_rules_calculator.go`) | "Program" means writing kernel routes or rules. For confd's, say "advertised" and "reject" CIDRs. |
| peer type | confd's peer scope: mesh, global, node or local_workload (`confd/pkg/backends/calico/bgp_processor.go`); BGPFilter `peerType`, eBGP or iBGP (`api/pkg/apis/projectcalico/v3/bgpfilter.go`) | "Peer type" is eBGP or iBGP. "Peer scope" for the confd kinds. |
| global | A global BGP peer (`confd/pkg/backends/calico/bgp_processor.go`); the `default` BGPConfiguration (`confd/pkg/backends/calico/client.go`); `/calico/bgp/v1/global` keys; GlobalNetworkPolicy; Felix's `DatastoreGlobal` source (`felix/config/config_params.go`) | "Default BGPConfiguration". Keep "global peer". |
| aggregation | BIRD block aggregation (`node/filesystem/etc/calico/confd/templates/bird_aggr.cfg.template`); `serviceLoadBalancerAggregation` (`api/pkg/apis/projectcalico/v3/bgpconfig.go`); the Goldmane aggregation window; flow aggregation | "Block aggregation", "LB service aggregation", "aggregation window". |
| sink / receive | Goldmane's `storage.Sink` output (`goldmane/pkg/storage/sink.go`); the `server.Sink.Receive` engine input (`goldmane/pkg/server/flow_collector_service.go`); the `storage.Receiver` stream feed (`goldmane/pkg/storage/deferred_builder.go`); BPF event sinks (`felix/dataplane/linux/bpf_events.go`) | "Sink" is Goldmane's emission output. "Flow intake" for its input. |
| reporter | The flow src/dst field; Felix flow log dispatchers; the health reporter; the node status reporter (`node/pkg/status/nodestatus.go`) | "Reporting side" for the src/dst field, "flow log dispatcher", "health reporter". |
| filter | A Goldmane query filter (`goldmane/proto/api.proto`); the Whisker visibility filter (`whisker-backend/pkg/auth/filter.go`); the BPF log filter (`felix/bpf/filter/filter.go`); the Felix validation filter; `endpointHostnameFilter` (`felix/calc/calc_graph.go`); BIRD filters; BGPFilter | Name which. "Visibility filter" for Whisker's per-user hiding. |
| certificate management | The operator CA `CertificateManager` (`operator/pkg/controller/certificatemanager/certificatemanager.go`); the Installation `certificateManagement` setting (`operator/api/v1/installation_types.go`); the render `CertificateManagement` component | "Operator CA", "`CertificateManagement` (Installation)". |
| virtual | The `virtual` affinity type (`libcalico-go/lib/ipam/ipam_types.go`); the IPAM GC's "virtual node" for stopped VMs (`kube-controllers/pkg/controllers/node/ipam.go`) | "Virtual" means the affinity type. "Stopped-VM bucket" for the GC. |
| IPAMConfig | The library config (`libcalico-go/lib/ipam/ipam_types.go` (`IPAMConfig`)); the storage `model.IPAMConfig` (`libcalico-go/lib/backend/model/ipam_config.go`); the CNI NetConf `ipam` section (`cni-plugin/pkg/types/types.go`) | "IPAMConfiguration" for the singleton; "NetConf ipam section" for CNI. |
| Inputs | `render.Inputs` (`operator/pkg/render/inputs.go`); `controller.Inputs` (`operator/pkg/controller/inputs.go`) | "Render inputs", "controller inputs". |
| lock | The datastore lock; the CNI IPAM lock (`cni-plugin/internal/pkg/utils/ipam_lock.go`); a Go mutex | "Datastore lock", "IPAM lock". |
| pass-through | The `DataplanePassthru` calculation node (`felix/calc/dataplane_passthru.go`); the operator's passthrough component (`operator/pkg/render/passthru.go`); a v3 kind with no update processor (`libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go`) | Name which. "Pass-through kind" for the v3 kind. |
