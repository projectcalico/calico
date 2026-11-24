# IPAM glossary

This file extends the [root GLOSSARY.md](../../GLOSSARY.md). The headline IPAM words (IP pool, block, block affinity, borrowing, handle, IP reservation, cooldown, leak) are defined there. This file covers the IPAM library, the calico-ipam plugin and the IPAM GC controller, which [DESIGN.md](DESIGN.md) and its sibling documents describe.

## Building blocks

Top layer of IPAM.

| Building block | Code | Responsible for |
|---|---|---|
| IPAM library | `libcalico-go/lib/ipam/interface.go` (`Interface`), `libcalico-go/lib/ipam/ipam.go` (`ipamClient`) | The public IPAM API that every caller uses: the CNI plugin, calico-node, calicoctl, kube-controllers. |
| calico-ipam | `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`add`, `del`) | Allocating and releasing a pod's addresses when kubelet runs the CNI plugin. |
| IPAM GC controller | `kube-controllers/pkg/controllers/node/ipam.go` (`IPAMController`) | Releasing leaked allocations, empty blocks and the IPAM state of deleted nodes, and reporting IPAM metrics. |
| Accounting tracker | `libcalico-go/lib/ipam/accounting/tracker.go` (`Tracker`) | Incremental per-pool and per-block counts, shared by the IPAM GC controller and `calicoctl ipam`. |

Layers inside the IPAM library, calico-ipam and the IPAM GC controller.

| Building block | Code | Responsible for |
|---|---|---|
| Assign state | `libcalico-go/lib/ipam/ipam.go` (`blockAssignState`) | One `AutoAssign` request: walk the affine blocks, then claim a new block or borrow. |
| Pool qualification | `libcalico-go/lib/ipam/pool_qualification.go` (`poolQualification`, `qualifyPools`) | Deciding which pools a request may draw from and which empty affine blocks a node keeps. |
| Pool claim | `libcalico-go/lib/ipam/pool_qualification.go` (`PoolClaim`) | The exported form of the pool qualification rule (`MayUse`), for callers outside the package. |
| Block reader and writer | `libcalico-go/lib/ipam/ipam_block_reader_writer.go` (`blockReaderWriter`) | Every compare-and-swap read and write of blocks, affinities and handles, including the affinity state machine. |
| Allocation block | `libcalico-go/lib/ipam/ipam_block.go` (`allocationBlock`) | In-memory block operations: assign, release, ownership updates, deallocation. |
| Allocation handle | `libcalico-go/lib/ipam/ipam_handle.go` (`allocationHandle`) | Per-handle, per-block counts mirrored into the IPAMHandle resource. |
| Address filter | `libcalico-go/lib/ipam/addr_filter.go` (`addrFilter`) | Skipping reserved addresses at block and ordinal granularity. |
| Reserved IPs | `libcalico-go/lib/ipam/accounting/reserved.go` (`ReservedIPs`) | The one implementation of reserved-set arithmetic. |
| VM handle helpers | `libcalico-go/lib/ipam/vmipam/ipam_kubevirt.go` (`CreateVMHandleID`, `EnsureActiveVMOwnerAttrs`) | VM-scoped handles and owner attributes for KubeVirt address persistence. |
| Network plugin hand-off | `cni-plugin/pkg/ipamplugin/in_process.go` (`inProcessExec`) | Running calico-ipam inside the `calico` process, and exec'ing any other IPAM plugin. |
| Sandbox handover step | `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`transferFromPriorSandbox`) | Moving an address the pod already holds onto the new sandbox's handle. |
| Release step | `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`ReleaseSandbox`, `releaseUnlisted`, `releaseHandle`) | Releasing by sandbox handle and legacy workload handle, or only the unlisted addresses. |
| Sync pass | `kube-controllers/pkg/controllers/node/ipam.go` (`syncIPAM`) | One GC pass: check allocations, release known leaks, deallocate cold IPs, release unused blocks, release nodes. |
| Allocation classifier | `kube-controllers/pkg/controllers/node/ipam.go` (`checkAllocations`, `judgeAllocation`) | Giving each allocation a verdict. |
| Allocation state | `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`allocationState`, `handleTracker`, `blockReleaseTracker`) | Allocations by node, the dirty-node set, the per-handle leak check and the empty-block rule. |
| IPAM feed | `kube-controllers/pkg/controllers/utils/ipam_feed.go` (`IPAMFeed`) | Feeding the accounting tracker from the datastore syncer. |

## Terms

Terms defined in the [root glossary](../../GLOSSARY.md) that apply in this component:

- [Affinity to a missing node](../../GLOSSARY.md#affinity--affine-to-a-missing-node)
- [Affinity type](../../GLOSSARY.md#affinity-type)
- [Allocation](../../GLOSSARY.md#allocation)
- [Intended use](../../GLOSSARY.md#intended-use)
- [IPAM GC controller](../../GLOSSARY.md#ipam-gc-controller)
- [Legacy workload handle](../../GLOSSARY.md#legacy-workload-handle)
- [Lent addresses](../../GLOSSARY.md#lent-addresses)
- [Pool containing the block](../../GLOSSARY.md#pool-containing-the-block)
- [Sandbox handle](../../GLOSSARY.md#sandbox-handle)
- [Strict affinity](../../GLOSSARY.md#strict-affinity)

### IPAM library

#### Ordinal
An address's index within its block.
Code: `libcalico-go/lib/backend/model/block.go` (`IPToOrdinal`).
_Avoid_: index (that also names an index into other tables)

#### Sequence number
A block-level write counter, with a per-ordinal copy.
Code: `libcalico-go/lib/backend/model/block.go` (`SequenceNumber`), `libcalico-go/lib/ipam/ipam_types.go` (`ReleaseOptions`).
_Avoid_: nothing known

#### Allocation attribute
The record kept for one allocated ordinal: its handle, active owner attributes, alternate owner attributes and release time.
Code: `libcalico-go/lib/backend/model/block.go` (`AllocationAttribute`).
_Avoid_: bare allocation (it means several things)

#### Active owner and alternate owner
The pod using an address now, and the other pod that holds it during a KubeVirt live migration. The active owner's attributes serialize under the JSON name `secondary`.
Code: `libcalico-go/lib/backend/model/block.go` (`ActiveOwnerAttrs`, `AlternateOwnerAttrs`).
_Avoid_: secondary (the JSON name of the active owner's attributes)

#### Pool qualification
The rule that decides which pools one request may draw addresses from and which empty affine blocks a node may keep. `PoolClaim` is its exported form.
Code: `libcalico-go/lib/ipam/pool_qualification.go` (`poolQualification`, `PoolClaim`).
_Avoid_: pool selection, pool eligibility

#### Pool resolution
Turning the pool names and CIDRs a request names into CIDRs, and nothing more.
Code: `libcalico-go/lib/ipam/pool_qualification.go` (`ResolvePools`).
_Avoid_: pool qualification (that is the later step)

#### Block affinity state
Where a block affinity is in its life: `pending` while being claimed, `confirmed` once it holds, and `pendingDeletion` while being released.
Code: `libcalico-go/lib/backend/model/block_affinity.go` (`BlockAffinityState`).
_Avoid_: confirmed on its own (it also means a confirmed leak), stale affinity (a different thing)

#### Cooling (in cooldown)
The state of a released address during its cooldown period. It still counts as in use.
Code: `libcalico-go/lib/backend/model/block.go` (`ReleasedAt`).
_Avoid_: pending release, quarantine

#### Cold IP
An address whose cooldown period has ended but that is still stored as allocated, because no deallocation has been saved for its block.
Code: `libcalico-go/lib/ipam/ipam_block.go` (`garbageCollect`), `kube-controllers/pkg/controllers/node/ipam.go` (`coldBlocks`).
_Avoid_: cooled-down address, expired address

#### Deallocation
Turning a cold IP into a free address in its block.
Code: `libcalico-go/lib/ipam/ipam_block.go` (`garbageCollect`, `blockFromBackend`).
_Avoid_: write-folded deallocation, release (that starts the cooldown), read-time GC

#### Free address
An address in a block that is not in use: never allocated, or deallocated.
Code: `libcalico-go/lib/backend/model/block.go` (`Unallocated`).
_Avoid_: available, unallocated

#### VM handle
The handle of the form `<network>.vmi.<namespace>.<vm>`, which persists across the pods of one KubeVirt VM.
Code: `libcalico-go/lib/ipam/vmipam/ipam_kubevirt.go` (`CreateVMHandleID`).
_Avoid_: bare handle (it means several things)

#### Windows-reserved handle
The literal handle `windows-reserved-ipam-handle`, which holds the first three and the last address of each Windows block.
Code: `libcalico-go/lib/ipam/accounting/allocation.go` (`WindowsReservedHandle`).
_Avoid_: reservation (that is the IP reservation resource)

#### Hostname label
The hashed-hostname label on a block affinity.
Code: `api/pkg/apis/projectcalico/v3/constants.go` (`LabelHostnameHash`), `libcalico-go/lib/ipam/ipam.go` (`UpgradeHost`).
_Avoid_: nothing known

#### Unreferenced
The accounting predicate that is true for an allocation whose owner no longer refers to it, at this instant. It is not yet a leak.
Code: `libcalico-go/lib/ipam/accounting/references.go` (`Unreferenced`).
_Avoid_: leak (before the grace period), orphan

### calico-ipam

#### calico-ipam
The Calico IPAM plugin program, which allocates from Calico IP pools.
Code: `cni-plugin/cmd/calico/calico.go` (`main`).
_Avoid_: the IPAM (that also means the library)

#### In-process IPAM
Running calico-ipam's code inside the `calico` network plugin's process instead of exec'ing it.
Code: `cni-plugin/pkg/ipamplugin/in_process.go` (`inProcessExec`).
_Avoid_: embedded IPAM

#### Sandbox
One pod sandbox, identified by its CNI container ID, that kubelet asked the plugin to network. A pod can have several over its life.
Code: `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`transferFromPriorSandbox`).
_Avoid_: container

#### Prior sandbox
An earlier sandbox of the same pod, whose handle may still hold addresses the new sandbox needs.
Code: `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`transferFromPriorSandbox`).
_Avoid_: old sandbox, previous sandbox, earlier sandbox, stale sandbox

#### Sandbox handover
Moving an address a pod holds under a prior sandbox's handle onto the new sandbox's handle without releasing it.
Code: `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`transferFromPriorSandbox`), `libcalico-go/lib/ipam/ipam.go` (`MoveIPToHandle`).
_Avoid_: reallocate (no release happens), reuse, transfer

#### Superseded sandbox
A sandbox the runtime gave up on while its ADD was still running, after a newer sandbox took the address.
Code: `cni-plugin/pkg/types/types.go` (`ErrCodeSandboxSuperseded`).
_Avoid_: abandoned sandbox

#### Address-not-ours error
The CNI error code that says a requested or handed-over address does not belong to the pod.
Code: `cni-plugin/pkg/types/types.go` (`ErrCodeAddressNotOurs`).
_Avoid_: nothing known

#### Kept addresses
The addresses a WorkloadEndpoint for another sandbox still lists.
Code: `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`keepAddresses`).
_Avoid_: protected addresses

#### Keep-aware release
Releasing only the addresses a WorkloadEndpoint no longer lists, so kept addresses stay allocated.
Code: `cni-plugin/pkg/k8s/ipam_keep.go` (`failedAddCleanup`, `releaseUnusedAddresses`).
_Avoid_: bare release (it means several things)

#### IPAM lock
A best-effort lock file held for the host across a calico-ipam ADD or release.
Code: `cni-plugin/internal/pkg/utils/ipam_lock.go` (`AcquireIPAMLockBestEffort`, `WithIPAMLock`).
_Avoid_: mutex

#### IPAM annotations
The pod and namespace annotations for requesting addresses and pools, such as `ipAddrs` and `ipv4pools`. The full list is in the IPAM CNI design document.
Code: `cni-plugin/pkg/k8s/k8s.go` (`applyIPAMAnnotations`), `design/ipam/ipam-cni.md`.
_Avoid_: nothing known

#### Single-network mode
The Windows mode that limits a node to one HNS network and one IPAM block.
Code: `cni-plugin/pkg/ipamplugin/ipam_plugin.go` (`WindowsUseSingleNetwork`).
_Avoid_: WindowsUseSingleNetwork, single-HNS-network mode

### IPAM GC controller

#### Incremental sync
An IPAM GC pass that checks only the nodes whose allocations changed since the last pass, the dirty nodes.
Code: `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`allocationState`, `iterDirty`).
_Avoid_: dirty scan

#### Allocation verdict
The IPAM GC controller's judgment of one allocation: in use, owner gone, or unused.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`judgeAllocation`).
_Avoid_: valid and leak (the words in `allocationIsValid`)

#### Candidate leak
An allocation judged not in use that has not yet been confirmed as a leak.
Code: `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`isCandidateLeak`).
_Avoid_: orphan

#### Confirmed leak
A leak whose grace period has passed, or whose owner is gone from a node that no longer exists.
Code: `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`isConfirmedLeak`, `markConfirmedLeak`).
_Avoid_: stale allocation

#### Replaced sandbox
An allocation whose handle names a container ID other than the one in the pod's `cni.projectcalico.org/containerID` annotation.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`fromReplacedSandbox`).
_Avoid_: stale sandbox

#### Handle tracker
The per-handle tracker of leak state in the IPAM GC controller.
Code: `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`handleTracker`).
_Avoid_: bare tracker (the accounting tracker is a separate thing)

#### Empty-block grace period
The grace the IPAM GC controller gives an empty block before releasing its affinity.
Code: `kube-controllers/pkg/controllers/node/ipam_allocation.go` (`blockReleaseTracker`).
_Avoid_: two-observation rule

#### Last affine block
The one affine block a node keeps even when empty.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`releaseUnusedBlocks`).
_Avoid_: nothing known

#### Stopped-VM bucket
The in-memory pseudo-node under which the controller files the addresses of stopped KubeVirt VMs that no node holds.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`stoppedVMNode`).
_Avoid_: virtual node (that clashes with the virtual affinity type)

#### VM recreation grace period
The minimum leak grace period for KubeVirt VM allocations.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`vmRecreationGracePeriod`).
_Avoid_: vmRecreationGracePeriod

#### Cold IP deallocation
The IPAM GC controller pass that deallocates cold IPs in blocks that nothing else has written.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`garbageCollectColdIPs`, `coldBlocks`).
_Avoid_: cold IP release, cold-IP GC

#### `kubernetesNodesByCalicoName`
The controller's lookup from a Calico Node name to the Kubernetes Node object.
Code: `kube-controllers/pkg/controllers/node/ipam.go` (`kubernetesNodesByCalicoName`).
_Avoid_: knode, cnode

#### IPAM feed
The building block that feeds the accounting tracker from the datastore syncer.
Code: `kube-controllers/pkg/controllers/utils/ipam_feed.go` (`IPAMFeed`).
_Avoid_: IPAM cache, shared tracker

## Words that need a qualifier

| Word | Meanings in play | Say |
|---|---|---|
| allocation | one assigned ordinal and its attribute, the model's `Allocations` slots, the GC's tracked allocation | allocation, ordinal slot, tracked allocation |
| claim | claiming a block affinity, `PoolClaim`, a handover timestamp | block claim, pool qualification, handover timestamp |
| IPAMConfig | the library's config type, the stored `IPAMConfig`, the CNI network configuration's `ipam` section | IPAMConfiguration, internal IPAMConfig, the `ipam` section of the network configuration |
| reserved | an IP reservation, the Windows-reserved handle, the accounting tracker's reserved classes | IP reservation, Windows-reserved handle, reserved class |
| stale | the unconfirmed-affinity error, an affinity to a missing node, a stale sandbox | stale affinity error, affinity to a missing node, prior sandbox |
| virtual | the virtual affinity type | virtual affinity |
| host and node | the Calico Node name in IPAM calls (`AffinityConfig.Host`, `MaxBlocksPerHost`), the Kubernetes Node name | Calico Node name, Kubernetes Node name |
| GC | the library's deallocation of cold IPs, the IPAM GC controller | deallocation, IPAM GC controller |
