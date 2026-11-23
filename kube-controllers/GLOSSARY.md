# kube-controllers glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `kube-controllers/` and the code it shares with `calicoctl` and `apiserver`.

## Building blocks

The top layer of the `calico component kube-controllers` process.

| Building block | Code | Responsible for |
|---|---|---|
| Controller control | `kube-controllers/pkg/kubecontrollers/run.go` (`controllerControl`) | Starts each enabled controller by name and restarts the whole process when the running config changes. |
| Run config controller | `kube-controllers/pkg/config/runconfig.go` (`RunConfigController`) | Watches the `default` KubeControllersConfiguration, merges environment variables over it, and reports the result in status. |
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
| Node controller | `kube-controllers/pkg/controllers/node/controller.go` (`NodeController`) | Owns four sub-controllers and fans Kubernetes Node and Pod deletes out to them. |
| IPAM GC controller | `kube-controllers/pkg/controllers/node/ipam.go` (`IPAMController`) | The IPAM GC code: leak detection and empty-block release. A sub-controller of the node controller. |
| Auto host endpoint controller | `kube-controllers/pkg/controllers/node/hostendpoints.go` (`autoHostEndpointController`) | Creates, updates and removes automatic host endpoints. A sub-controller. |
| Node label controller | `kube-controllers/pkg/controllers/node/labels.go` (`nodeLabelController`) | Copies Kubernetes Node labels onto the Calico Node in etcdv3 mode. A sub-controller. |
| Node deleter | `kube-controllers/pkg/controllers/node/node_deleter.go` (`nodeDeleter`) | Deletes Calico Nodes whose Kubernetes Node is gone, in etcdv3 mode. A sub-controller. |
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

**Controller**:
Any object implementing `Run(stopCh)`, registered by name in the controller control. The word does not mean a controller-runtime Reconciler; kube-controllers does not use that framework.
Code: `kube-controllers/pkg/controllers/controller/controller.go` (`Controller`).
_Avoid_: reconciler

**Feed-driven controller**:
A controller that subscribes to the DataFeed through `RegisterWith`, queues updates to its own goroutine, and coalesces bursts with a kick. The node controller's sub-controllers, the LoadBalancer controller and the policy name migrator are feed-driven.
Code: `kube-controllers/pkg/controllers/node/hostendpoints.go` (`RegisterWith`).
_Avoid_: data feed consumer, syncer, watcher

**Workqueue controller**:
A controller built on a Kubernetes informer, a workqueue and `processNextItem` workers. The IP pool, tier and migration controllers and the four mirroring controllers are workqueue controllers.
Code: `kube-controllers/pkg/controllers/tier/tier_controller.go` (`processNextItem`).
_Avoid_: informer controller

**Mirroring controllers**:
The namespace, service account, policy and pod controllers, which copy Kubernetes objects into Calico resources through a ResourceCache.
Code: `kube-controllers/pkg/controllers/namespace/namespace_controller.go` (`namespaceController`).
_Avoid_: Kubernetes-to-Calico sync controllers

**Policy controller**:
The mirroring controller for Kubernetes NetworkPolicies. Some older comments use "policy controller" for all of kube-controllers.
Code: `kube-controllers/pkg/controllers/networkpolicy/policy_controller.go` (`policyController`).
_Avoid_: policy controller for kube-controllers as a whole

**Sub-controller**:
A controller owned and started by the node controller rather than by the controller control.
Code: `kube-controllers/pkg/controllers/node/controller.go` (`NodeController`).
_Avoid_: controller, unqualified

**Controller control**:
The object that registers each enabled controller by name, starts it, and exits the process when the running config changes.
Code: `kube-controllers/pkg/kubecontrollers/run.go` (`controllerControl`).
_Avoid_: controller manager

**Deferred CRD controller**:
A wrapper that starts an inner controller only once a named CRD is established, and stops it if the CRD goes away. "Deferred" here is unrelated to the KubeVirt deferred informers in `libcalico-go`.
Code: `kube-controllers/pkg/controllers/controller/deferred.go` (`DeferredCRDController`).
_Avoid_: lazy controller

### Feed and caches

**DataFeed**:
The single shared datastore syncer that streams Calico resources and IPAM blocks to registered handlers, one update handler and one status handler per key type.
Code: `kube-controllers/pkg/controllers/utils/syncer.go` (`DataFeed`).
_Avoid_: the syncer, data feed (two words)

**RegisterWith**:
The method by which a feed-driven controller subscribes to the DataFeed for keys and sync status.
Code: `kube-controllers/pkg/controllers/node/hostendpoints.go` (`RegisterWith`).
_Avoid_: watch

**IPAMFeed**:
The component that keeps one shared `accounting.Tracker` of pool usage current from the DataFeed, so every IPAM reader sees the same counts.
Code: `kube-controllers/pkg/controllers/utils/ipam_feed.go` (`IPAMFeed`).
_Avoid_: IPAM cache

**ResourceCache**:
The desired-state cache whose changed keys feed the workqueue of a mirroring controller.
Code: `kube-controllers/pkg/cache/cache.go` (`ResourceCache`).
_Avoid_: informer cache, Calico cache

**Periodic reconciler**:
The ResourceCache's periodic diff of its contents against a datastore list, run every `RECONCILER_PERIOD`.
Code: `kube-controllers/pkg/cache/cache.go` (`performDatastoreSync`).
_Avoid_: reconcile (that means one workqueue pass)

**Reconcile**:
One workqueue pass that brings a single key's Calico state in line with its Kubernetes source.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`reconcileKey`).
_Avoid_: sync, for a workqueue pass

**Prime**:
Setting a ResourceCache entry without queuing an update, used to seed state that is already in the datastore.
Code: `kube-controllers/pkg/cache/cache.go` (`Prime`).

**syncToDatastore**:
The worker step that writes or deletes one key so the datastore matches the ResourceCache.
Code: `kube-controllers/pkg/controllers/namespace/namespace_controller.go` (`syncToDatastore`).

**processNextItem**:
The worker loop that pops one workqueue key, handles it, and marks it done.
Code: `kube-controllers/pkg/controllers/tier/tier_controller.go` (`processNextItem`).

**Dropped key**:
A workqueue key given up after `maxRetries` failures. Only the periodic informer resync brings it back.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`maxRetries`).
_Avoid_: failed key

**Kick**:
A non-blocking send on a channel that coalesces many triggers into one pending pass.
Code: `kube-controllers/pkg/controllers/node/controller.go` (`kick`).

**Full pass**:
One pass over every object, requested by a kick instead of handling keys one at a time. The IP pool controller's `reconcileKey` is the single key that stands for a full pass.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`reconcileKey`).
_Avoid_: resync

**Start-of-day pass**:
Work a controller runs once after its informers and the DataFeed are in sync and before its workers start.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`Run`).
_Avoid_: initial sync

### Configuration and restart

**RunConfig**:
The effective configuration after merging environment variables over the `default` KubeControllersConfiguration. Its status counterpart is `status.runningConfig`.
Code: `kube-controllers/pkg/config/runconfig.go` (`RunConfig`).
_Avoid_: config, unqualified

**ENABLED_CONTROLLERS**:
The environment variable listing the controllers to run. When set, it overrides the controller list in the KubeControllersConfiguration. `profile` is accepted as an alias for `namespace`.
Code: `kube-controllers/pkg/config/config.go` (`EnvEnabledControllers`).

**Status file**:
The readiness file `/status/status.json`, read by the `check-status` command alongside the HTTP health aggregator.
Code: `kube-controllers/pkg/status/status.go`.

### IP pool and tier controllers

**Finalizer-guarded deletion**:
Deletion held up by a finalizer that a controller removes once dependents are gone. The IP pool finalizer waits for the pool's blocks to be released, and the tier finalizer waits for every policy in the tier to be deleted by the user.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`IPPoolFinalizer`) and `api/pkg/apis/projectcalico/v3/tier.go` (`TierFinalizer`).
_Avoid_: cascading delete (that is Kubernetes owner references)

**Pool sort category**:
The precedence (active, terminating, disabled, new) deciding which of several overlapping pools stays allocatable.
Code: `kube-controllers/pkg/controllers/ippool/pool_controller.go` (`poolSortCategory`).

**AddressSpaceNearlyFull**:
The IP pool condition set at 80 percent use for pools of 32 or more addresses.
Code: `kube-controllers/pkg/controllers/ippool/nearly_full.go` (`reconcileNearlyFull`).

### IPAM GC and node sub-controllers

**Auto host endpoint**:
A host endpoint that kube-controllers creates and owns, from the node's auto-create setting or from a template.
Code: `kube-controllers/pkg/controllers/node/hostendpoints.go` (`autoHostEndpointController`, `isAutoHostEndpoint`).
_Avoid_: auto-HEP

**Node deleter**:
The sub-controller that deletes Calico Nodes whose Kubernetes Node is gone. It and the node label controller run only in etcdv3 mode, because a KDD Calico Node is a Kubernetes Node.
Code: `kube-controllers/pkg/controllers/node/node_deleter.go` (`nodeDeleter`).
_Avoid_: node deletion controller

**WorkloadEndpointData**:
The subset of a WorkloadEndpoint (pod name, namespace, labels, service account) that the pod controller owns.
Code: `kube-controllers/pkg/converter/pod_converter.go` (`WorkloadEndpointData`).

### LoadBalancer controller

**Calico-managed LoadBalancer**:
A Service whose LoadBalancer address Calico assigns from Calico IPAM, selected by the `calico` load balancer class and steered by the `projectcalico.org/ipv4pools` and `ipv6pools` annotations.
Code: `kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go` (`loadBalancerController`).

### v1-to-v3 CRD migration

**DatastoreMigration**:
The `migration.projectcalico.org` resource, named `v1-to-v3`, that holds the migration's phase, progress and conditions.
Code: `kube-controllers/pkg/apis/migration/v1/types.go` (`DatastoreMigration`).
_Avoid_: APIServerToCRDs (that is its Go spec type)

**Migration phase**:
One of Pending, Migrating, WaitingForConflictResolution, Converged, Complete or Failed. A Failed migration is retried by deleting and recreating the DatastoreMigration.
Code: `kube-controllers/pkg/apis/migration/v1/types.go` (`DatastoreMigrationPhase`).
_Avoid_: state

**Conflict**:
A `projectcalico.org/v3` resource that already exists with a different spec from its `crd.projectcalico.org/v1` source.
Code: `kube-controllers/pkg/controllers/migration/registry.go`.

**Migration order**:
The integer group assigned to each kind, deciding which kinds are copied first (tiers first, IPAM late).
Code: `kube-controllers/pkg/controllers/migration/resources.go` (`NewMigrators`).
_Avoid_: priority

**Resource migrator**:
The per-kind step that lists the v1 resources, converts them, creates the v3 resources and compares specs.
Code: `kube-controllers/pkg/controllers/migration/migrators/migrator.go` (`ResourceMigrator`).

**APIService handover**:
Removing the `v3.projectcalico.org` APIService that points at the Calico apiserver, saving it for rollback, and letting kube-aggregator register the CRD-backed one. The operator's APIService cutover is a different mechanism.
Code: `kube-controllers/pkg/controllers/migration/controller.go`.
_Avoid_: APIService swap

**Drain period**:
The wait after locking `crd.projectcalico.org/v1` and before removing the APIService, letting in-flight IPAM writes finish.
Code: `kube-controllers/pkg/controllers/migration/controller.go`.
_Avoid_: drain (that is a node drain in the Flannel migration)

**Migration rollout window**:
The time between locking `crd.projectcalico.org/v1` and every component restarting in `projectcalico.org/v3` mode. The v1 ClusterInformation stays locked after convergence, so components not yet restarted block CNI operations.
Code: `kube-controllers/pkg/controllers/migration/controller.go`.
_Avoid_: CNI freeze

### Policy name migration and Flannel migration

**Stored policy name**:
A policy's name in its datastore key, the name of the `crd.projectcalico.org/v1` object. For pre-v3.32 default-tier policies it carries the `default.` tier prefix. The tier prefix has no meaning outside this legacy migration code.
Code: `kube-controllers/pkg/controllers/networkpolicy/policymigrate.go` (`NeedsMigration`).
_Avoid_: v1 name, legacy name

**API policy name**:
A policy's `ObjectMeta` name in `projectcalico.org/v3`, which never has a tier prefix.
Code: `kube-controllers/pkg/controllers/networkpolicy/policymigrate.go` (`MigratePolicyKVP`).
_Avoid_: v3 name, bare name

**Flannel migration**:
The node-by-node move of a Flannel cluster to Calico VXLAN. The Flannel migration controller must be the only controller enabled.
Code: `kube-controllers/pkg/controllers/flannelmigration/migration_controller.go`.
_Avoid_: migration, unqualified
