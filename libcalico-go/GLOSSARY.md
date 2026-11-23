# libcalico-go glossary

This file extends the [root GLOSSARY.md](../GLOSSARY.md). Shared datastore words (datastore, KDD, v3 resource, v1 model, syncer, update processor, in-sync) are defined there. This file covers how the library implements them. IPAM has its own glossary in [design/ipam/GLOSSARY.md](../design/ipam/GLOSSARY.md).

## Building blocks

Top layer of the datastore client library.

| Building block | Code | Responsible for |
|---|---|---|
| Backend client | `libcalico-go/lib/backend/api/api.go` (`Client`) | KVPair create, read, update, delete, list and watch against one datastore. |
| KDD backend | `libcalico-go/lib/backend/k8s/client.go` (`KubeClient`) | Sending each kind to its per-kind client, whether CRD-backed or derived from a core Kubernetes object. |
| etcdv3 backend | `libcalico-go/lib/backend/etcdv3/etcdv3.go` (`etcdV3Client`) | Storing KVPairs at their default paths in etcd. |
| Syncer framework | `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`watcherSyncer`) | Merging one watcher cache per resource type into a single syncer. |
| Syncer definitions | `libcalico-go/lib/backend/syncersv1/` | The resource list and update processors for each consumer: Felix, BGP, tunnel IP allocation and node status. |
| clientv3 | `libcalico-go/lib/clientv3/resources.go` (`resources`) | The v3 resource API: validate, default, convert to a KVPair, call the backend client. |
| Validator | `libcalico-go/lib/validator/v3/validator.go` (`Validate`) | Struct-tag validation of v3 resources. |

Layers inside the KDD backend and the syncer framework.

| Building block | Code | Responsible for |
|---|---|---|
| Per-kind client | `libcalico-go/lib/backend/k8s/resources/client.go` (`K8sResourceClient`) | Create, read, update, delete, list and watch for one kind. |
| Custom resource client | `libcalico-go/lib/backend/k8s/resources/customresource.go` (`customResourceClient`) | The generic per-kind client for CRD-backed kinds, in either backing API group. |
| Converter | `libcalico-go/lib/backend/k8s/conversion/conversion.go` (`Converter`) | Turning Pods into WorkloadEndpoints, Namespaces and ServiceAccounts into Profiles, and Kubernetes network policies into Calico policies. |
| Watcher cache | `libcalico-go/lib/backend/watchersyncer/watchercache.go` (`watcherCache`) | The list-then-watch loop for one resource type, deduplicated by revision. |
| Update processor | `libcalico-go/lib/backend/watchersyncer/watchersyncer.go` (`SyncerUpdateProcessor`) | Converting one v3 KVPair into zero or more v1-model KVPairs. |
| Dedupe buffer | `libcalico-go/lib/backend/syncersv1/dedupebuffer/dedupe_buffer.go` (`DedupeBuffer`) | A client-side queue between a syncer and its consumer that replaces queued values for the same key. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Aggregated v3 API](../GLOSSARY.md#aggregated-v3-api)
- [Backing API group](../GLOSSARY.md#backing-api-group)
- [BGP syncer](../GLOSSARY.md#bgp-syncer)
- [Datastore syncer](../GLOSSARY.md#datastore-syncer)
- [Dedupe buffer](../GLOSSARY.md#dedupe-buffer)
- [etcd-to-KDD migration](../GLOSSARY.md#etcd-to-kdd-migration)
- [Node name](../GLOSSARY.md#node-name)
- [Pass-through kind](../GLOSSARY.md#pass-through-kind)
- [Syncer output](../GLOSSARY.md#syncer-output)
- [v3.Node name](../GLOSSARY.md#v3node-name)

**projectcalico.org/v3 CRDs**:
Calico resources stored as CRDs in the `projectcalico.org/v3` API group, with no apiserver in front of them.
Code: `libcalico-go/lib/backend/k8s/resources/apigroups.go` (`BackingAPIGroupV3`).
_Avoid_: v3 CRDs (without the group), CRD mode

**crd.projectcalico.org/v1 CRDs**:
Calico resources stored as CRDs in the `crd.projectcalico.org/v1` API group. This is the storage behind the aggregated v3 API.
Code: `libcalico-go/lib/backend/k8s/resources/apigroups.go` (`BackingAPIGroupV1`).
_Avoid_: v1 CRDs (without the group), v1 API

**Storage kind**:
How KDD holds one kind: CRD-backed, stored as a custom resource, or derived, computed from a core Kubernetes object and never stored.
Code: `libcalico-go/lib/backend/k8s/client.go` (`NewKubeClientForConfig`).
_Avoid_: CRD mode

**Felix syncer**:
The datastore syncer behind the `felix` syncer type. It carries ClusterInformation and FelixConfiguration always, and with `isLeader` set it adds policies, tiers, network sets, IP pools, Nodes, Profiles, endpoints, BGP configuration, IPAM blocks and the rest of Felix's inputs.
Code: `libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go` (`New`).

**Tunnel IP allocation syncer**:
The datastore syncer behind the `tunnel-ip-allocation` syncer type, which carries IPPool and one Node for calico-node's tunnel address allocator.
Code: `libcalico-go/lib/backend/syncersv1/tunnelipsyncer/tunnelipsyncer.go` (`New`).

**Node status syncer**:
The datastore syncer behind the `node-status` syncer type, which carries CalicoNodeStatus only.
Code: `libcalico-go/lib/backend/syncersv1/nodestatussyncer/nodestatussyncer.go` (`New`).

**Watcher cache**:
The loop inside a datastore syncer that lists one resource type, then watches it and forwards changes. A watcher cache that cannot watch re-lists on a timer instead.
Code: `libcalico-go/lib/backend/watchersyncer/watchercache.go` (`watcherCache`).
_Avoid_: informer (that is client-go's), cache (on its own)

**Polling state**:
The watcher cache state in which the cache cannot watch, re-lists periodically, and still counts as in-sync.
Code: `libcalico-go/lib/backend/watchersyncer/watchercache.go` (`listTriggeredPolling`, `watchTriggeredPolling`).

**`crdInstalled`**:
The watcher cache state in which the CRD for its kind is absent. The cache counts as in-sync and delivers no data.
Code: `libcalico-go/lib/backend/watchersyncer/watchercache.go` (`crdInstalled`).

**`ConflictResolvingCacheUpdateProcessor`**:
An update processor for kinds whose v1-model key cannot be derived from the v3 name. When two v3 resources map to one v1 key, it keeps the one with the lowest name.
Code: `libcalico-go/lib/backend/syncersv1/updateprocessors/conflictresolvingcacheproc.go` (`NewConflictResolvingCacheUpdateProcessor`).

**Config update processor**:
An update processor that expands one FelixConfiguration or ClusterInformation resource into one v1-model key per field, either global or per node.
Code: `libcalico-go/lib/backend/syncersv1/updateprocessors/configurationprocessor.go` (`NewConfigUpdateProcessor`).
_Avoid_: config fan-out (Typha's fan-out is a different thing)

**Per-field config keys**:
The v1-model keys a config update processor emits, one for each field of a configuration resource.
Code: `libcalico-go/lib/backend/model/felixconfig.go` (`GlobalConfigKey`, `HostConfigKey`).

**`EnsureInitialized`**:
The first-run step that creates ClusterInformation (version, cluster GUID, `DatastoreReady`) and the protected tiers.
Code: `libcalico-go/lib/clientv3/client.go` (`EnsureInitialized`).

**Policy key**:
The v1-model key for a policy, made of kind, namespace and name.
Code: `libcalico-go/lib/backend/model/policy.go` (`PolicyKey`).

## Words that need a qualifier

| Word | Meanings in play | Say |
|---|---|---|
| v1 | the v1 model, the legacy v1 API types, the crd.projectcalico.org/v1 API group, `ClientV1` resource clients | v1 model, legacy v1 API, crd.projectcalico.org/v1 CRDs |
| v3 | the v3 API types, the projectcalico.org/v3 API group as CRDs, the aggregated v3 API | v3 resource, projectcalico.org/v3 CRDs, aggregated v3 API |
| cache | watcher cache, snapshot cache, binary snapshot cache, an update processor's own cache | name which |
| node | a calculation node, the Kubernetes Node, the v3.Node, the machine | node name, v3.Node name, host |
