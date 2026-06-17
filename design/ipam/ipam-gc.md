<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM garbage collection

The IPAM GC lives in [`kube-controllers/pkg/controllers/node/`](../../kube-controllers/pkg/controllers/node/), **not** `pkg/controllers/ipam/`. There is no `ipam` controller; if
you came looking for the GC and didn't find it, look in `node`.

Main file: `ipam.go` (~1600 lines). Supporting types in `ipam_allocation.go`. Pool / block mapping in `pool_manager.go`. Cross-component picture is in the [index](./DESIGN.md); the
block and handle state machines are defined in [`./ipam-datastore.md`](./ipam-datastore.md) and [`./ipam-core-library.md`](./ipam-core-library.md) - this file references them
rather than restating.

The controller is a single goroutine fed by `syncerUpdates`, `syncChan`, `nodeDeletionChan`, and `podDeletionChan`. Events are coalesced via `utils.ProcessBatch`. Periodic interval
is `LeakGracePeriod / 2`, defaulting to 5 minutes; dirty-only scans run between full scans.

## Leak detection

Invariants:

- **Allocations are valid until proven leaked.** Missing metadata, unknown owner type, KubeVirt-not-installed - all default to valid. Tightening any of these without a real reason
  will spuriously release live IPs.
- **Two observations gate every release.** A candidate leak must survive the grace period and re-validate immediately before the release call. One observation is never enough.
- **Tunnel IPs validate via node existence, not pods.** The pod-based validity check doesn't apply.

`checkAllocations` (`ipam.go:823`) walks every allocation on every scanned node and classifies it. The decision tree:

```
windows-reserved:                skip
not pod and not tunnel:          mark node "can't delete"
tunnel address:                  defer until node-deletion decision
allocationIsValid(preferCache):  markValid
!kubernetesNodeExists:           markConfirmedLeak (immediate)
isVMAllocation:                  markLeak(max(5min, leakGracePeriod))
leakGracePeriod set:             markLeak(leakGracePeriod)
```

After the walk, if every allocation on a node is released and no valid ones remain, the node's tunnel IPs are confirmed-leaked and the node is added to `nodesToRelease`.

`allocationIsValid` (`ipam.go:999`) is the truth check. The design-relevant rules:

- **Tunnel IPs validate via node existence only.** They never validate via pods. Mixing the paths would release a live tunnel IP whenever the pod-side check failed.
- **Missing `pod` / `namespace` attributes ⇒ assume valid.** Conservative on purpose. Tightening this without a real reason will release allocations made by paths that don't
  stamp the attrs.
- **Multus produces multiple WorkloadEndpoints per pod.** The IP must appear in at least one `wep.Spec.IPNetworks` to be valid. A single-WEP check would falsely release
  secondary-network IPs.
- **Pod lookup mode is preferCache vs live.** Cache for the node-deleted path (where the source data is presumed stale), live for sync. A live read can win against the cache in the
  rare case the cache is behind.

Candidate vs confirmed leak is timer-based: `markLeak(grace)` sets `leakedAt`; once `time.Since(leakedAt) > grace` the allocation is confirmed. `markValid` clears both fields if a
later sync re-validates the allocation. The transition is what the [grace periods](#grace-periods) protect.

**Review notes**

- `allocationIsValid` compares `pod.Spec.NodeName` against `attrs["node"]`. Stale source data makes valid allocations look like leaks -
  https://github.com/projectcalico/calico/issues/12257. Don't expand the comparison without thinking about stale-source-data scenarios.
- Missing `pod` / `namespace` attributes must remain "assume valid." Tightening this without a real reason will cause spurious releases.
- Tunnel IPs do not validate via pods. Only the node-existence path releases them.
- Don't add per-IP API GETs in this loop. The hot path uses informer cache reads after https://github.com/projectcalico/calico/pull/10333.
- The `ipam.go:1043` TODO on pod-NodeName mismatch is unresolved. Currently releases the old allocation; the comment expresses uncertainty. Don't touch without understanding the
  migration cases.

## Grace periods

Three grace periods coexist and defend against different races.

**Leak grace period** (`leakGracePeriod`, config). Generic pod-allocation grace. Defaults from `KubeControllersConfiguration`; zero means "GC disabled for that allocation class."
Set on `markLeak`; transitions candidate => confirmed only after `time.Since(leakedAt) > grace`. Defends against the pod-restart-between-syncs race: sync N sees the pod gone and
marks `leakedAt`; sync N+1 sees the new pod on the same allocation and `markValid` clears the timer before it expires.

**VM recreation grace period** (`defaultVMRecreationGracePeriod = 5 * time.Minute`, `ipam.go:81`). Floor for VM allocations. Even with a shorter `leakGracePeriod`, VM allocations
use `max(5min, leakGracePeriod)` so VM restart and live migration can complete without the GC yanking the IP out from under the new pod. Without this floor, a live migration that
paused on the destination side longer than the leak grace would release the IP and reassign it elsewhere before the migration finished.

**Empty-block grace period** (`blockReleaseTracker`, `ipam_allocation.go:26`). Two-observation rule: a block must be observed empty on two consecutive syncs, spanning the grace
period, before its affinity is released. First `markEmpty(cidr)` returns false and records the timestamp; the second returns true once the grace period has elapsed. `markInUse`
clears the timestamp on any allocation activity. Defends against the "block emptied transiently while a fresh pod is about to claim it" race - releasing too early forces a fresh
affinity claim, which is costly and can flap with the dataplane.

**Final re-validate before release.** Independent of grace periods, `garbageCollectKnownLeaks` (`ipam.go:1229`) calls `allocationIsValid(a, preferCache)` once more for every
confirmed leak immediately before passing it to `ReleaseIPs`. This is the last defence against the pod-restart race: a pod that came back between scan and release will re-validate
here and skip the release call entirely.

**Review notes**

- The 5-minute VM floor is load-bearing for live migration. Don't lower it without coordinating with the KubeVirt persistence story documented in [`./ipam-cni.md`](./ipam-cni.md).
- The block-release "two consecutive empty observations" rule is the only thing preventing block-affinity flap. Skipping the second observation will produce
  reclaim/reclaim/re-acquire churn under normal allocation activity.
- The final re-validate in `garbageCollectKnownLeaks` is non-negotiable. Removing it for "optimization" reintroduces the pod-restart-race class of bug.
- Grace periods are not a substitute for sequence numbers. The two protect different things - timing windows vs concurrent reuse. See
  [`./ipam-core-library.md`](./ipam-core-library.md) on `ReleaseOptions.SequenceNumber`.

## Handle reconciliation

The invariant: **all-or-none per handle.** Either every IP on a handle is confirmed-leaked and gets released together, or the entire handle is skipped this sync. Mixing the two
states desyncs the per-block `IPAMHandle` counters from the actual block bitmap and the controller permanently loses track of live IPs.

`handleTracker` (`ipam_allocation.go:73`) is the per-handle view: handle ID => set of allocations the GC believes share it. `setAllocation` and `removeAllocation` keep it in sync
with the in-memory allocation maps. The key method is `isConfirmedLeak` (`ipam_allocation.go:91`), which returns true only when **every** allocation associated with the handle is
confirmed-leaked.

`garbageCollectKnownLeaks` (`ipam.go:1229`) gates every release through this check:

```go
if !c.handleTracker.isConfirmedLeak(a.handle) {
    continue
}
```

If even one IP on a handle is still valid, the entire handle is skipped this sync. Otherwise the per-block `IPAMHandle` counters (`Block[blockCIDR]int`) would desync from the
actual block bitmap and the controller would lose track of the live IPs.

Periodic sweep: every full sync rebuilds `confirmedLeaks` via `checkAllocations`, calls `garbageCollectKnownLeaks`, then `releaseUnusedBlocks` and `releaseNodes` (`syncIPAM`,
`ipam.go:1174`). Unreleased items roll over to the next sync.

The GC calls `ReleaseIPs` rather than [`ReleaseByHandle`](./ipam-core-library.md) because it operates at the per-allocation level (`ReleaseOptions`), preserving sequence-number
protection for each ordinal.

**Review notes**

- All-or-none per handle is the handle-counter integrity invariant. Don't bypass `handleTracker.isConfirmedLeak` for an "optimization" -
  https://github.com/projectcalico/calico/pull/12713 codifies this as a safety rule.
- Don't delete a handle just because its in-memory count looks zero. A CNI ADD may be in flight against a fresh allocation on the same handle.
- Auxiliary-state reconcilers must use revision-stable CAS and never delete a non-empty handle. The orphan-handle work in https://github.com/projectcalico/calico/pull/12278 and
  https://github.com/projectcalico/calico/pull/12713 must hold this line.
- `ReleaseIPs` plumbs sequence numbers through `ReleaseOptions`. Any new release path here must do the same.
- The crash at `ipam.go:1281` (`log.Fatalf("BUG: unable to find allocation for release options")`) is reachable if released options can't be mapped back to tracked allocations.

## Empty block release

Invariants:

- **A node keeps at least one affinity block.** Releasing the last block forces a fresh claim on the next pod and adds per-pod CAS contention that the affinity model exists to
  prevent.
- **Two consecutive empty observations before release.** A single empty sync is not enough - a pod about to allocate would lose the block to the GC and trigger reclaim churn.

`releaseUnusedBlocks` (`ipam.go:746`) walks `emptyBlocks` and releases via `ReleaseBlockAffinity(mustBeEmpty=true)`. The GC's job is to ensure correctness before calling - the
`mustBeEmpty` precondition in libcalico is a backstop, not the primary safety. Two skip rules carry design weight: a block that is the node's only affinity block is held (otherwise
the next pod allocation pays for a fresh claim) and a node mid-Flannel-migration is held entirely (the migrator is still wiring up its initial state).

Interaction with `StrictAffinity`. When `StrictAffinity=true`, a node cannot allocate from blocks it doesn't own. Releasing an empty block on a strict-affinity node forces the next
pod allocation to claim a fresh block. Under contention, multiple nodes race for the same free block and lose on CAS; with tight pools the allocation fails outright. The grace
period and single-block floor exist precisely so this churn doesn't compound.

Interaction with `MaxBlocksPerHost`. When `MaxBlocksPerHost` is non-zero, the per-node block cap is enforced at `AutoAssign` time (see
[`./ipam-core-library.md`](./ipam-core-library.md)). The GC does not enforce or read this value - it releases empty blocks regardless. But the doc-vs-code mismatch on the default
is a recurring complaint (https://github.com/projectcalico/calico/issues/9462); if you touch the default, also touch the docs.

**Review notes**

- The "skip if it's the node's only block" rule prevents allocation-stall when a node briefly has zero pods. Don't remove it.
- `mustBeEmpty=true` is a hard precondition - the caller must have verified emptiness. The two-observation grace period is what makes the GC's verification trustworthy.
- `StrictAffinity` interaction: releasing too eagerly on strict-affinity nodes causes claim-churn between nodes. Tune the grace period, don't remove it.
- `MaxBlocksPerHost` defaults are doc-vs-code drift (https://github.com/projectcalico/calico/issues/9462). Touching the default requires a docs update.
- Pending block affinities must be treated as absent when deciding ownership - https://github.com/projectcalico/calico/pull/6003, /1712, /6867.

## Batching and rate-limiting

`ReleaseIPs` is bounded per sync (a soft DoS guard against catastrophic leaks) and unreleased items roll over via `confirmedLeaks` rather than failing the sync. Retry uses
`workqueue.NewTypedMaxOfRateLimiter` - exponential backoff plus a token bucket - so a controller hammering against a flapping datastore self-throttles instead of compounding the
storm. Constants and exact bucket sizes live in `ipam.go`; the design contract is that they exist, not what their current values are.

Partial-failure handling is the normal case under load: per-block CAS contention against active allocators is expected, `ReleaseIPs` returns the subset actually released, and the
rest roll over. Code that treats partial release as fatal will produce noisy alerts with no operational signal.

**Review notes**

- The per-sync cap is a soft DoS guard. Don't remove it without a replacement throttle.
- Per-block CAS contention is expected. Don't tune backoff to retry harder; tune to retry less aggressively on conflict.
- `ReleaseIPs` partial-failure is normal under load.

## Metrics

Per-pool, per-node gauges, registered lazily as pools appear. The two metrics that carry operational meaning beyond "current count" are:

- **`ipam_allocations_gc_candidates`** - allocations in candidate-leak state. Returns to zero after the grace period elapses. A sustained non-zero value means the GC is stuck,
  typically on a handle conflict (one IP on the handle is still valid, so the entire handle is held).
- **`ipam_allocations_gc_reclamations`** - counter of successful leak releases. In a healthy cluster this is near-zero and stable. Sustained increase is the signal that there's a
  real leak source to investigate.

`ipam_allocations_in_use`, `ipam_allocations_borrowed`, and `ipam_blocks` are trend metrics; their absolute values vary with pool size and pod count. Legacy single-dimension
variants exist for backward compatibility.

`updateMetrics` recomputes from scratch every sync - one walk over all blocks, no incremental state. The full-recompute *is* the consistency check; switching to incremental updates
without a separate consistency check loses the protection.

**Review notes**

- `ipam_allocations_gc_candidates > 0` for extended periods is the canonical "GC is stuck" signal. Alert on it.
- `ipam_allocations_gc_reclamations` rate is the canonical "we have a real leak somewhere" signal. Alert on it.
- Don't switch `updateMetrics` to incremental updates without a separate consistency check. The current full-recompute is the consistency check.
- The in-memory state maps must agree at all times. `assertConsistentState` in `ipam_test.go` is the canonical invariant check; any new map mutation needs a test that exercises it.
  The v3.32 memory-leak family (https://github.com/projectcalico/calico/pull/12277, /12286, /12287, /12288) all came from "added to one path, forgot another."

## Testing the GC

Two harnesses cover the GC and they are not interchangeable:

- **`assertConsistentState`** in [`kube-controllers/pkg/controllers/node/ipam_test.go`](../../kube-controllers/pkg/controllers/node/ipam_test.go) is the canonical end-of-test
  invariant check. It cross-walks every in-memory map (`allBlocks`, `allocationsByBlock`, `allocationState`, `handleTracker`, `confirmedLeaks`, `nodesByBlock`, `blocksByNode`,
  `emptyBlocks`) and asserts they agree. Every test that mutates the controller's state must call it. The v3.32 memory-leak family
  (https://github.com/projectcalico/calico/pull/12277, /12286, /12287, /12288) all came from "added to one path, forgot another" - the consistency check catches that class
  directly.
- **[`hack/cmd/ipam-hammer/`](../../hack/cmd/ipam-hammer/)** is the race-reproduction harness for allocation and GC paths. Use it before declaring a race-fix complete. Unit
  tests can't exercise the CAS / timing windows that hammer can.

**Review notes**

- A new map mutation needs an `assertConsistentState` call in the corresponding test. Skipping it ships a memory-leak class bug.
- A "fixes a race" PR without an `ipam-hammer` run on the before/after binaries is not done. Manual reasoning is not a substitute.
- For changes to block-level invariants, extend the table tests in [`libcalico-go/lib/ipam/ipam_block_test.go`](../../libcalico-go/lib/ipam/ipam_block_test.go) rather than
  adding ad-hoc tests; the table is where reviewers look first.

## Keep in sync with

- [`./ipam-datastore.md`](./ipam-datastore.md) - block / affinity state machine, sequence numbers, `mustBeEmpty=true` precondition.
- [`./ipam-core-library.md`](./ipam-core-library.md) - `ReleaseIPs` / `ReleaseByHandle` semantics, handle conventions, sequence-number protection.
- [`./ipam-cni.md`](./ipam-cni.md) - CNI side of the KubeVirt persistence handshake the VM grace period defends.
- [`../../kube-controllers/pkg/controllers/node/`](../../kube-controllers/pkg/controllers/node/) - a `DESIGN.md` stub in that directory will point back here.
