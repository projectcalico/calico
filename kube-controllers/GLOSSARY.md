# kube-controllers glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `kube-controllers/` and the code it shares with `calicoctl` and `apiserver`.

## Building blocks

The top layer of the `calico component kube-controllers` process.

| Building block | Code | Responsible for |
|---|---|---|
| Controller group | `kube-controllers/pkg/kubecontrollers/run.go` (`controllerControl`) | Starts each enabled controller by name and restarts the whole process when the running config changes. |
| Configuration manager | `kube-controllers/pkg/config/runconfig.go` (`RunConfigController`) | Watches the `default` KubeControllersConfiguration, merges environment variables over it, and reports the result in status. |
| Restart wrapper | `kube-controllers/pkg/kubecontrollers/command.go` (`cmdwrapper.WrapSelf`) | Re-executes the inner process when it exits with the restart return code. |
| DataFeed | `kube-controllers/pkg/controllers/utils/syncer.go` (`DataFeed`) | One datastore syncer over Calico resources and IPAM blocks, fanned out to registered handlers by key type. |
| IPAMFeed | `kube-controllers/pkg/controllers/utils/ipam_feed.go` (`IPAMFeed`) | Keeps one shared IPAM accounting tracker current from the DataFeed. |
| Deferred CRD controller | `kube-controllers/pkg/controllers/controller/deferred.go` (`DeferredCRDController`) | Runs an inner controller only while a named CRD is established. |
| ResourceCache | `kube-controllers/pkg/cache/cache.go` (`ResourceCache`) | Desired-state cache that queues changed keys and periodically diffs itself against the datastore. |
| etcdv3 compactor | `kube-controllers/pkg/kubecontrollers/run.go` | Runs periodic etcd compaction in etcdv3 mode. |

The controllers `controllerControl` starts, one layer down.

| Controller | Code | Responsible for |
|---|---|---|
| IP pool controller | `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`IPPoolController`) | Pool finalizer, the `Allocatable` condition from CIDR overlap, and the `AddressSpaceNearlyFull` condition. |
| Tier controller | `kube-controllers/pkg/controllers/tier/tier_controller.go` (`TierController`) | Tier finalizer and the Terminating condition until no policy references the tier. |
| Node controller | `kube-controllers/pkg/controllers/node/controller.go` (`NodeController`) | Owns four sub-controllers and fans Kubernetes Node object and Pod deletes out to them. |
| IPAM GC controller | `kube-controllers/pkg/controllers/node/ipam.go` (`IPAMController`) | The IPAM GC code: leak detection and empty-block release. A sub-controller of the node controller. |
| Auto host endpoint controller | `kube-controllers/pkg/controllers/node/hostendpoints.go` (`autoHostEndpointController`) | Creates, updates and removes automatic host endpoints. A sub-controller. |
| Node label controller | `kube-controllers/pkg/controllers/node/labels.go` (`nodeLabelController`) | Copies Kubernetes Node object labels onto the Calico Node object in etcdv3 mode. A sub-controller. |
| Node deleter | `kube-controllers/pkg/controllers/node/node_deleter.go` (`nodeDeleter`) | Deletes Calico Node objects whose Kubernetes Node object is gone, in etcdv3 mode. A sub-controller. |
| LoadBalancer controller | `kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go` (`loadBalancerController`) | Allocates and releases Service LoadBalancer addresses from Calico IPAM and writes Service status. |
| Migration controller | `kube-controllers/pkg/controllers/migration/controller.go` | Runs the phase machine of the v1-to-v3 CRD migration. |
| Policy name migrator | `kube-controllers/pkg/controllers/networkpolicy/policy_name_migrator.go` (`policyMigrator`) | Renames policies whose stored policy name differs from their API policy name. |
| Namespace controller | `kube-controllers/pkg/controllers/namespace/namespace_controller.go` (`namespaceController`) | Mirrors Namespaces to `kns.` Profiles. |
| Service account controller | `kube-controllers/pkg/controllers/serviceaccount/serviceaccount_controller.go` (`serviceAccountController`) | Mirrors ServiceAccounts to `ksa.` Profiles. |
| Policy controller | `kube-controllers/pkg/controllers/networkpolicy/policy_controller.go` (`policyController`) | Mirrors Kubernetes NetworkPolicies to Calico NetworkPolicies named `knp.default.<name>`. |
| Pod controller | `kube-controllers/pkg/controllers/pod/pod_controller.go` (`podController`) | Syncs pod labels and service account onto existing WorkloadEndpoints. |
| Flannel migration controller | `kube-controllers/pkg/controllers/flannelmigration/migration_controller.go` | Moves a Flannel cluster to Calico VXLAN node by node. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Config-change restart](../GLOSSARY.md#config-change-restart)
- [Datastore lock](../GLOSSARY.md#datastore-lock)
- [IPAM GC controller](../GLOSSARY.md#ipam-gc-controller)
- [Policy name migration](../GLOSSARY.md#policy-name-migration)
- [v1-to-v3 CRD migration](../GLOSSARY.md#v1-to-v3-crd-migration)

### Controller shapes

#### Controller
Any object implementing `Run(stopCh)`, registered by name in the controller group. The word does not mean a controller-runtime Reconciler; kube-controllers does not use that framework.
Code: `kube-controllers/pkg/controllers/controller/controller.go` (`Controller`).
_Avoid_: reconciler

#### Feed-driven controller
A controller that is driven by updates from the DataFeed. The node controller's sub-controllers, the LoadBalancer controller and the policy name migrator are feed-driven.
Code: `kube-controllers/pkg/controllers/node/hostendpoints.go` (`RegisterWith`).
_Avoid_: data feed consumer, syncer, watcher

#### Workqueue controller
A controller built on a Kubernetes informer, a workqueue and `processNextItem` workers. The IP pool, tier and migration controllers and the four mirroring controllers are workqueue controllers.
Code: `kube-controllers/pkg/controllers/tier/tier_controller.go` (`processNextItem`).
_Avoid_: informer controller

#### Mirroring controllers
The namespace, service account, policy and pod controllers, which copy Kubernetes objects into Calico resources through a ResourceCache.
Code: `kube-controllers/pkg/controllers/namespace/namespace_controller.go` (`namespaceController`).
_Avoid_: Kubernetes-to-Calico sync controllers

#### Policy controller
The mirroring controller for Kubernetes NetworkPolicies.
Code: `kube-controllers/pkg/controllers/networkpolicy/policy_controller.go` (`policyController`).
_Avoid_: policy controller for kube-controllers as a whole

#### Sub-controller
A controller owned and started by the node controller rather than by the controller group.
Code: `kube-controllers/pkg/controllers/node/controller.go` (`NodeController`).
_Avoid_: controller, unqualified

#### Controller group
The set of enabled controllers that kube-controllers registers, starts and restarts together.
Code: `kube-controllers/pkg/kubecontrollers/run.go` (`controllerControl`).
_Avoid_: controller control, controller manager (that is `ControllerManager`)

#### Configuration manager
The kube-controllers building block that watches the `default` KubeControllersConfiguration and produces the configuration kube-controllers runs with.
Code: `kube-controllers/pkg/config/runconfig.go` (`RunConfigController`).
_Avoid_: run config controller

#### Deferred CRD controller
A wrapper around an inner controller that depends on a named CRD. "Deferred" here is unrelated to the KubeVirt deferred informers in `libcalico-go`.
Code: `kube-controllers/pkg/controllers/controller/deferred.go` (`DeferredCRDController`).
_Avoid_: lazy controller

### Feed and caches

#### DataFeed
The single shared datastore syncer that streams Calico resources and IPAM blocks to the controllers.
Code: `kube-controllers/pkg/controllers/utils/syncer.go` (`DataFeed`).
_Avoid_: the syncer, data feed (two words)

#### RegisterWith
The method by which a feed-driven controller subscribes to the DataFeed for keys and sync status.
Code: `kube-controllers/pkg/controllers/node/hostendpoints.go` (`RegisterWith`).
_Avoid_: watch

#### IPAMFeed
The component that holds one shared `accounting.Tracker` of pool usage.
Code: `kube-controllers/pkg/controllers/utils/ipam_feed.go` (`IPAMFeed`).
_Avoid_: IPAM cache

#### ResourceCache
The desired-state cache used by the mirroring controllers.
Code: `kube-controllers/pkg/cache/cache.go` (`ResourceCache`).
_Avoid_: informer cache, Calico cache

#### Periodic reconciler
The ResourceCache's periodic diff of its contents against a datastore list.
Code: `kube-controllers/pkg/cache/cache.go` (`performDatastoreSync`).
_Avoid_: reconcile (that means one workqueue pass)

#### Reconcile
One workqueue pass that brings a single key's Calico state in line with its Kubernetes source.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`reconcileKey`).
_Avoid_: sync, for a workqueue pass

#### Prime
Setting a ResourceCache entry without queuing an update.
Code: `kube-controllers/pkg/cache/cache.go` (`Prime`).
_Avoid_: nothing known

#### syncToDatastore
The worker step that writes or deletes one key so the datastore matches the ResourceCache.
Code: `kube-controllers/pkg/controllers/namespace/namespace_controller.go` (`syncToDatastore`).
_Avoid_: syncToCalico

#### processNextItem
The worker loop of a workqueue controller.
Code: `kube-controllers/pkg/controllers/tier/tier_controller.go` (`processNextItem`).
_Avoid_: processNextWorkItem

#### Dropped key
A workqueue key that a controller has given up on.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`maxRetries`).
_Avoid_: failed key

#### Kick
A non-blocking send on a channel that coalesces many triggers into one pending pass.
Code: `kube-controllers/pkg/controllers/node/controller.go` (`kick`).
_Avoid_: fullScanNextSync

#### Full pass
One pass over every object, as opposed to one workqueue key at a time.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`reconcileKey`).
_Avoid_: resync

#### Start-of-day pass
Work a controller runs once at startup.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`Run`).
_Avoid_: initial sync

### Configuration and restart

#### RunConfig
The effective configuration kube-controllers runs with. Its status counterpart is `status.runningConfig`.
Code: `kube-controllers/pkg/config/runconfig.go` (`RunConfig`).
_Avoid_: config, unqualified

#### Status file
The readiness file `/status/status.json`.
Code: `kube-controllers/pkg/status/status.go`.
_Avoid_: nothing known

### IP pool and tier controllers

#### Finalizer-guarded deletion
Deletion held up by a finalizer until dependents are gone.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`IPPoolFinalizer`) and `api/pkg/apis/projectcalico/v3/tier.go` (`TierFinalizer`).
_Avoid_: cascading delete (that is Kubernetes owner references)

#### Pool sort category
The precedence category of an IP pool: active, terminating, disabled or new.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`poolSortCategory`).
_Avoid_: nothing known

#### AddressSpaceNearlyFull
An IP pool condition reporting that the pool's address space is nearly used up.
Code: `kube-controllers/pkg/controllers/ippool/nearly_full.go` (`reconcileNearlyFull`).
_Avoid_: nothing known

### IPAM GC and node sub-controllers

#### Auto host endpoint
A host endpoint that kube-controllers creates and owns.
Code: `kube-controllers/pkg/controllers/node/hostendpoints.go` (`autoHostEndpointController`, `isAutoHostEndpoint`).
_Avoid_: auto-HEP

#### Node deleter
The sub-controller that deletes Calico Node objects whose Kubernetes Node object is gone.
Code: `kube-controllers/pkg/controllers/node/node_deleter.go` (`nodeDeleter`).
_Avoid_: node deletion controller

#### Trimmed workload endpoint
The subset of a WorkloadEndpoint (pod name, namespace, labels, service account) that the pod controller owns.
Code: `kube-controllers/pkg/converter/pod_converter.go` (`WorkloadEndpointData`).
_Avoid_: nothing known

### LoadBalancer controller

#### Calico-managed LoadBalancer
A Service of type LoadBalancer whose address Calico assigns from Calico IPAM.
Code: `kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go` (`loadBalancerController`).
_Avoid_: bare LoadBalancer (any Service of that type, whoever assigns the address)

#### Orphaned LoadBalancer addresses
Addresses in Calico IPAM under a LoadBalancer handle that no Service holds.
Code: `kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go` (`syncIPAM`).
_Avoid_: leak (that is a workload address past its grace period), unclaimed addresses

### v1-to-v3 CRD migration

#### DatastoreMigration
The `migration.projectcalico.org` resource, named `v1-to-v3`, that holds the migration's phase, progress and conditions.
Code: `kube-controllers/pkg/apis/migration/v1/types.go` (`DatastoreMigration`).
_Avoid_: APIServerToCRDs (that is its Go spec type)

#### Migration phase
One of Pending, Migrating, WaitingForConflictResolution, Converged, Complete or Failed.
Code: `kube-controllers/pkg/apis/migration/v1/types.go` (`DatastoreMigrationPhase`).
_Avoid_: state

#### Conflict
A `projectcalico.org/v3` resource that already exists with a different spec from its `crd.projectcalico.org/v1` source.
Code: `kube-controllers/pkg/controllers/migration/registry.go`.
_Avoid_: ResourceMismatch

#### Migration order
The integer group assigned to each kind in the migration.
Code: `kube-controllers/pkg/controllers/migration/resources.go` (`NewMigrators`).
_Avoid_: priority

#### Resource migrator
The per-kind migrator of one resource kind from `crd.projectcalico.org/v1` to `projectcalico.org/v3`.
Code: `kube-controllers/pkg/controllers/migration/migrators/migrator.go` (`ResourceMigrator`).
_Avoid_: migration (it means several things; say v1-to-v3 CRD migration)

#### APIService handover
Replacing the `v3.projectcalico.org` APIService that points at the Calico apiserver with the CRD-backed one. The operator's APIService cutover is a different mechanism.
Code: `kube-controllers/pkg/controllers/migration/controller.go`.
_Avoid_: APIService swap

#### Drain period
The wait during the migration that lets in-flight IPAM writes finish.
Code: `kube-controllers/pkg/controllers/migration/controller.go`.
_Avoid_: drain (that is a node drain in the Flannel migration)

#### Migration rollout window
The time between locking `crd.projectcalico.org/v1` and every component restarting in `projectcalico.org/v3` mode.
Code: `kube-controllers/pkg/controllers/migration/controller.go`.
_Avoid_: CNI freeze

### Policy name migration and Flannel migration

#### Stored policy name
A policy's name in its datastore key, the name of the `crd.projectcalico.org/v1` object. For pre-v3.32 default-tier policies it carries the `default.` tier prefix. The tier prefix has no meaning outside this legacy migration code.
Code: `kube-controllers/pkg/controllers/networkpolicy/policymigrate.go` (`NeedsMigration`).
_Avoid_: v1 name, legacy name

#### API policy name
A policy's `ObjectMeta` name in `projectcalico.org/v3`, which never has a tier prefix.
Code: `kube-controllers/pkg/controllers/networkpolicy/policymigrate.go` (`MigratePolicyKVP`).
_Avoid_: v3 name, bare name

#### Flannel migration
The node-by-node move of a Flannel cluster to Calico VXLAN.
Code: `kube-controllers/pkg/controllers/flannelmigration/migration_controller.go`.
_Avoid_: migration, unqualified
