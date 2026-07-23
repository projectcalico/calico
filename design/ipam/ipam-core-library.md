<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM core library

This sub-design covers the core IPAM library in `libcalico-go/lib/ipam/`. It is the in-process API every IPAM caller goes through (CNI plugin, kube-controllers, `node`,
`calicoctl`, operator). The cross-component picture - data model, consumers, repo split - lives in the [index](./DESIGN.md).

## Public API surface

The library's contract is `Interface` in [`interface.go`](../../libcalico-go/lib/ipam/interface.go); that file is the source of truth for method signatures and is not restated
here. A few methods carry design-relevant constraints worth calling out:

- **`AutoAssign`** returns block-masked CIDRs, not `/32` (or `/128`). Callers narrow at the boundary. This is load-bearing for the CNI plugin's per-block route programming.
- **`ReleaseIPs`** takes `ReleaseOptions` with a sequence number; every release path must plumb it through (see [CAS retry and sequence numbers](#cas-retry-and-sequence-numbers)).
- **`SetOwnerAttributes`** is KubeVirt-only and swaps owner attributes under preconditions, without releasing and re-allocating. Felix's live-migration monitor is the only non-CNI
  caller.
- **`GetIPAMConfig` / `SetIPAMConfig`** read and write the v1 `IPAMConfig` / v3 `IPAMConfiguration` singleton. Field-level bounds are enforced by the CRD schema in k8s mode, but the
  cross-field rules live only in `SetIPAMConfig` - a direct CRD write can persist a config that violates them, which the library rejects on read (see [IPAMConfig](#ipamconfig)).

**Review notes**

- New CRDs / new API methods need operator RBAC; see https://github.com/tigera/operator/pull/4775 (May 2026). Easy to miss on backports.
- Don't leak `crd.projectcalico.org/v1` types through new public APIs. The `lib/v3` -> `lib/internalapi` rename (https://github.com/projectcalico/calico/pull/11870) exists to keep
  that boundary clean.
- `AutoAssign` returning block-masked CIDRs is load-bearing for the CNI plugin's routing. Don't quietly switch to `/32`.

## AutoAssign and host affinity

Three invariants frame this section:

- **Two-phase claim.** A new block goes `pending → confirmed`. Pending affinities are treated as absent for ownership and routing; only confirmed affinities participate. This is
  what makes the claim race resolvable.
- **`MaxBlocksPerHost` caps claims, not allocations.** Once a node reaches the cap it can still fill blocks it already owns. The cap is the only gate on new-block claims.
- **`StrictAffinity=true` is the only way to suppress non-affine fallback.** Anything that needs "borrow nothing" semantics must set it, not invent a parallel switch.

`AutoAssign` is the hot path. Entry point is `autoAssign` in [`ipam.go`](../../libcalico-go/lib/ipam/ipam.go). The walk splits at three chokepoints:
`prepareAffinityBlocksForHost` resolves the node + pools and lists existing affinities; `findOrClaimBlock` walks affine blocks and lazily reconstructs an `IPAMBlock` if an affinity
exists but the block doesn't (recovery for a node that crashed mid-claim); `findUsableBlock` claims a new block via the two-phase `pending → confirmed` protocol or, with
`StrictAffinity=false`, falls back to `randomBlockGenerator` over non-affine blocks.

A few non-obvious design points:

- The random generator seeds from a hostname hash so retries hit the same blocks in the same order. Two nodes competing for the same pool deterministically diverge instead of
  thrashing.
- An empty affine block becomes eligible for reclaim by another node after `EmptyBlockMinReclaimAge` (1 minute). The same value is what makes [empty-block
  release](./ipam-gc.md#empty-block-release) safe.
- The block cap is `min(global MaxBlocksPerHost, request-level)`, defaulting to 20 if both are zero. Once a node reaches it, `allowNewClaim` is forced false; existing blocks still
  fill.

**Review notes**

- The `pending -> confirmed` two-phase claim is intentional; don't "optimize" it away. It's what makes claim races resolvable. See
  https://github.com/projectcalico/calico/pull/6003, https://github.com/projectcalico/calico/pull/1712.
- Treat pending block affinities as if absent when deciding ownership or advertising routes.
- Pre-existing blocks may lack `AffinityType`; default to `"host"` on read. https://github.com/projectcalico/calico/pull/11179 was a crash from this assumption.
- Pool resolution is in the hot path. `ResolvePools` was hand-optimized in https://github.com/projectcalico/calico/pull/9891 - preserve the fast path.
- `MaxBlocksPerHost` defaults are a recurring doc/code drift point (https://github.com/projectcalico/calico/issues/9462). If you change the default in code, update the docs in the
  same PR.

## CAS retry and sequence numbers

Two invariants frame this section:

- **Every IPAM write is CAS.** No write bypasses `backend.Client.Update`. The retry loop is bounded; on non-conflict errors it surfaces, not swallows.
- **Per-ordinal sequence numbers detect ABA.** A release that doesn't match the stored sequence number is rejected. Every release path must plumb the sequence number through;
  dropping it reopens the pod-reuse race.

All `IPAMBlock`, `BlockAffinity`, and `IPAMHandle` updates are CAS on resource version via `backend.Client.Update`. The library wraps every write in a bounded retry loop
(`datastoreRetries = 100`, declared in [`ipam.go`](../../libcalico-go/lib/ipam/ipam.go)). On `ErrorResourceUpdateConflict` the loop re-fetches and retries; on any other error it
exits immediately and surfaces to the caller.

Each `IPAMBlock` carries a `SequenceNumber` that [`updateBlock`](../../libcalico-go/lib/ipam/ipam_block_reader_writer.go) increments on every write, and per-ordinal
`SequenceNumberForAllocation[ord]` records the block's sequence number at allocation time. A `ReleaseOptions.SequenceNumber` from the caller is compared against the stored value;
on mismatch the library returns `ErrorBadSequenceNumber` and the IP is **not** released. This prevents the GC from freeing an ordinal that was reallocated to a new pod between scan
and release - the new pod's allocation bumps the block sequence number, so stale release options won't match.

Block release is parallelised per block via a semaphore sized at `GOMAXPROCS`.

**Review notes**

- Every release path must plumb the sequence number through. A release path that drops it on the floor is a regression. See `ReleaseOptions.SequenceNumber`.
- Don't mutate the in-memory `*model.AllocationBlock` (KVPair) before persisting. Update the value, call `updateBlock`, then update auxiliary state (handle, host info).
  https://github.com/projectcalico/calico/pull/12697 was exactly this bug: partial mutation persisted via a retry loop after the actual write was skipped.
- The `Deallocated` / `Unallocated` queue cycling is load-bearing for IP-reuse delay. New code that punches the bitmap directly skipping the queue breaks rate-limited reuse
  (relevant to https://github.com/projectcalico/calico/issues/12638).
- Older blocks may not have per-ordinal sequence numbers. New code must tolerate the absent case (default + heal-forward), not crash.

## IP release and cooldown

Releasing an IP and freeing it for reuse are two distinct steps, separated by a configurable cooldown. This sits on top of the `Unallocated` FIFO queue: the queue cycles freed
ordinals so the longest-idle IP is reused first, and the cooldown adds a wall-clock floor on how soon any released IP can come back.

- **Release marks the IP, it does not free it.** `release` / `releaseByHandle` ([`ipam_block.go`](../../libcalico-go/lib/ipam/ipam_block.go)) clear the handle association and stamp
  the allocation's `ReleasedAt` with the current time. The ordinal stays in `Allocations` - the IP is no longer tied to a workload, but it is not yet available for reallocation. An
  IP in this state is "in cooldown".
- **`garbageCollect` deallocates IPs whose cooldown has elapsed.** It moves an ordinal to `Unallocated`, clears its sequence number, and prunes the now-unreferenced attribute, but
  only once `ReleasedAt` is older than `IPCooldownSeconds`. With `IPCooldownSeconds=0` the IP is deallocated on the next GC pass. This is the only place ordinals move to
  `Unallocated`.
- **GC runs implicitly on every read by the IPAM client.** `blockFromBackend` calls `garbageCollect` whenever a block is loaded. On write paths (`AutoAssign`, `release`,
  `releaseByHandle`, `SetOwnerAttributes`) the reclamation folds into the same CAS write, so a new allocation can reuse IPs that finished cooling down in one transaction. On
  read-only paths the GC'd view is computed and then discarded - the caller sees cooled-down IPs as not-yet-reusable, but nothing is persisted.
- **Blocks with no write activity need a backstop.** Because read-only GC doesn't persist, a block that sees no further allocation or release never gets rewritten, so its
  cooled-down IPs would never be deallocated. The kube-controllers GC closes that gap; see [ipam-gc](./ipam-gc.md#cold-ip-garbage-collection).

**Review notes**

- Release and deallocation are distinct states. Code that counts "allocated" IPs has to decide whether cooldown counts as allocated, released, or its own state - don't silently fold
  it into one. `calicoctl ipam check` treats it as its own state.
- A release call against an IP already in cooldown is not an error - it's already released. Don't return an error for the idempotent case.
- The cooldown floor is on top of the `Unallocated` FIFO, not a replacement for it. Both exist; don't remove the queue cycling thinking the timestamp covers it.

## Handle IDs

A handle ID is an opaque string from the library's point of view, but its **format is a convention every IPAM caller has to follow** because `calicoctl datastore migrate` parses
the tunnel prefixes to rewrite them on node rename.

Conventions in use:

| Caller | Handle ID format |
|---|---|
| CNI workload (default) | `<network-name>.<container-id>` via `cni-plugin/internal/pkg/utils.GetHandleID`. For the default network, `<network-name>` is `k8s-pod-network`. |
| CNI workload (KubeVirt persistent) | `<network-name>.<namespace>-<vm-name>` so live-migrated VMs keep the same handle. |
| IPIP tunnel | `ipip-tunnel-addr-<node>` |
| VXLAN tunnel | `vxlan-tunnel-addr-<node>`; IPv6 variant is `vxlan-v6-tunnel-addr-<node>` (note the `-v6-` infix, not a suffix) |
| WireGuard tunnel | `wireguard-tunnel-addr-<node>`; IPv6 variant is `wireguard-v6-tunnel-addr-<node>` |
| Windows-reserved | literal `windows-reserved-ipam-handle` |
| LoadBalancer | `lb-<hash>`, where `<hash>` is the sha256 of `<service>-<namespace>-<uid>` (lowercased), truncated to the DNS1123 limit. Built by `createHandle` in `kube-controllers/pkg/controllers/loadbalancer/loadbalancer_controller.go`. Not to be confused with the `virtual:load-balancer` affinity string. |

The CNI plugin also keeps a separate **workload-ID** form (`<namespace>.<pod>`) and releases by both on DEL so that allocations made before a CRI container-ID change can still be
found - see [`./ipam-cni.md`](./ipam-cni.md).

**Review notes**

- The GC and `calicoctl ipam check` classify tunnel allocations by `AttributeType` and `Node` spec respectively, not by the handle prefix - so a handle-format change doesn't touch
  them, but it does need an `AttributeType` for the GC to recognize it.
- A new tunnel handle prefix needs migration code in `calicoctl datastore migrate` (`calicoctl/calicoctl/commands/datastore/migrate/migrateipam.go`), which remaps tunnel-type
  handles on node rename. That parser's prefix list is v4-only today (`ipip-tunnel-addr-`, `vxlan-tunnel-addr-`, `wireguard-tunnel-addr-`), so it already skips the `*-v6-tunnel-addr-`
  handles - add v6 prefixes there if you touch it.
- Skipping the workload-ID release on CNI DEL leaks IPs whose container-ID changed under CRI. Don't drop the second release call.

## IPAMConfig

`IPAMConfig` is a singleton CR. Defaults are applied on read by `GetIPAMConfig` when the CR is missing, so callers can rely on "there is always a config". Writes come from the
operator reconciling user-facing config and from end users editing the CR directly (v1 `IPAMConfig` or v3 `IPAMConfiguration`). Field-level bounds are enforced by the CRD schema in
k8s mode (kubebuilder markers on `IPAMConfigurationSpec`: `MaxBlocksPerHost` range, the `KubeVirtVMAddressPersistence` enum), so direct kubectl writes don't bypass those. But the
cross-field rules below live only in `SetIPAMConfig`, not in the CRD schema - a client that writes the CR directly can persist a config that violates them, which the library then
rejects on read:

- `StrictAffinity=false` + `AutoAllocateBlocks=false` is rejected (would mean "never allocate anywhere", which is never what the user wants).
- `MaxBlocksPerHost > 0` requires `StrictAffinity=true`.

Fields:

| Field | Effect |
|---|---|
| `StrictAffinity` | Disables non-affine fallback in `AutoAssign`. Windows forces true; see [ipam-cni](./ipam-cni.md#platform-differences). |
| `MaxBlocksPerHost` | Per-host cap on the number of affine blocks. 0 means default (20). Once a host hits the cap, `allowNewClaim` is forced false; existing blocks still fill. |
| `AutoAllocateBlocks` | When false, `AutoAssign` will never claim a new block - only allocate from blocks the host already owns. |
| `KubeVirtVMAddressPersistence` | Default for whether KubeVirt VM addresses survive VM restart / migration. Auto-detection is on by default. |
| `IPCooldownSeconds` | Minimum age of a released IP before it can be reused. Release stamps the IP's `ReleasedAt`; `garbageCollect` only deallocates it once this many seconds have passed. 0 deallocates on the next GC pass. Capped at 1200. See [IP release and cooldown](#ip-release-and-cooldown). |

**Review notes**

- The default-when-missing behavior is load-bearing. New required fields need a default plus heal-forward; don't add a field that crashes when absent.
- `MaxBlocksPerHost > 0` only makes sense with `StrictAffinity=true`; the validator enforces this. If you relax the validator, you also need to define what "borrow blocks but cap
  our own" means - it currently isn't defined.
- Field-level checks belong in kubebuilder markers (enforced by the CRD in k8s mode); the cross-field rules live only in `SetIPAMConfig`. A direct kubectl write skips the latter and
  persists config the library rejects on read, so a new cross-field rule must live in the library, not on a single caller.
- A new field needs the v3 type, conversion, and operator reconciliation in addition to v1, or it isn't reachable through user-facing config.

## Error taxonomy

Sentinel errors are defined in [`ipam_errors.go`](../../libcalico-go/lib/ipam/ipam_errors.go) and at the top of `ipam.go`. The design points worth carrying here are the error
classes, not the names:

- **Transient.** `ErrorResourceUpdateConflict`, `errBlockClaimConflict`, `errStaleAffinity`. The retry loop swallows these; callers never see them. Exiting the retry loop without
  consuming a transient is a bug.
- **Validation.** `IPAMConfigConflictError`, `ErrStrictAffinity`, `ErrNoQualifiedPool`, `ErrBlockLimit`. Surface to callers; user-visible. New validation rules attach here.
- **Stop-and-re-evaluate.** `ErrorBadSequenceNumber`, `errBlockNotEmpty`. The release path treats these as "skip this allocation and try again next sync", not as failure. A caller
  that catches and proceeds anyway defeats the sequence-number / empty-block protocols.

Internal sentinels (`noFreeBlocksError`, `errBlockClaimConflict`, `errStaleAffinity`) are not part of the public API; translate to the exported `Err*` values before returning.

**Review notes**

- `mustBeEmpty=true` on `ReleaseBlockAffinity` is a hard precondition. The caller verifies emptiness; the GC's two-consecutive-empty-observations check is what gates this.
- A new release code path that catches `ErrorBadSequenceNumber` and proceeds anyway defeats the protocol. Skip and re-evaluate.

## Keep in sync with

- [`./ipam-datastore.md`](./ipam-datastore.md) - the CAS protocol and sequence-number scheme are defined together with the backend.
- [`./ipam-cni.md`](./ipam-cni.md) - the CNI plugin duplicates the handle-ID convention; changes here that affect the format need to land there too.
- [`../../libcalico-go/lib/ipam/`](../../libcalico-go/lib/ipam/) - a `DESIGN.md` stub in that directory points back here.
