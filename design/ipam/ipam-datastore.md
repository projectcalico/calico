<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM datastore

The backend datastore layer for IPAM: the four CRDs and their KDD wrappers under [`libcalico-go/lib/backend/k8s/resources/`](../../libcalico-go/lib/backend/k8s/resources/) and
the model types under [`libcalico-go/lib/backend/model/`](../../libcalico-go/lib/backend/model/). Cross-component picture is in the [index](./DESIGN.md). Paired with
[`ipam-core-library.md`](./ipam-core-library.md) - the CAS protocol and sequence-number scheme are defined together; this file covers the datastore side.

## IPAMBlock

An `IPAMBlock` is a contiguous slice of a pool, default /26 for IPv4 and /122 for IPv6. The block is the CAS unit: one object per slice, holding every per-IP record. Layout is in
[`libcalico-go/lib/backend/model/block.go`](../../libcalico-go/lib/backend/model/block.go); the design points that aren't obvious from the struct:

- **The `Unallocated` queue is FIFO and that's load-bearing.** Allocation pops the head; release pushes the tail. Cycling through the queue is what enforces rate-limited IP reuse -
  a fresh allocation gets the IP that's been free the longest, not the IP that was just released. Code that punches the bitmap directly, bypassing the queue, breaks reuse delay.
  See https://github.com/projectcalico/calico/issues/12638.
- **`SequenceNumber` is paired with per-ordinal `SequenceNumberForAllocation`.** Together they detect ABA on release; see [Sequence numbers](#sequence-numbers).
- **`Affinity` is `host:<name>` or `virtual:<name>`.** `nil` means unaffine. `virtual:` is used by the LoadBalancer controller; `host:` is the standard pod/tunnel case.
- **`Deleted` is a soft-delete marker.** Readers must filter; see [Soft vs hard delete](#soft-vs-hard-delete).

**Review notes**

- `blockSize` is immutable for existing blocks. Changing the pool's `blockSize` does not re-slice. https://github.com/projectcalico/calico/issues/10778.
- The `Unallocated` queue cycling is load-bearing for IP-reuse delay. Code that punches the bitmap directly breaks reuse rate-limiting.
- Don't mutate the in-memory `*model.AllocationBlock` before persisting. Persist via `updateBlock`, then update auxiliary state. See
  https://github.com/projectcalico/calico/pull/12697.

## BlockAffinity

A `BlockAffinity` records that a host (or virtual owner) claims a block. State machine, driven by
[`ipam_block_reader_writer.go`](../../libcalico-go/lib/ipam/ipam_block_reader_writer.go): `∅ → pending → confirmed → pendingDeletion → ∅`.

- **`pending`** - host wants the block, hasn't proven ownership. Treat as if absent for ownership / route decisions.
- **`confirmed`** - host owns the block. The block's `Affinity` field matches; route advertisement is safe.
- **`pendingDeletion`** - host is giving the block up. Other hosts must not re-claim until the affinity row is gone.

Transitions only happen via `ipam_block_reader_writer.go` under CAS on resource version. The library is the only writer; the GC and `calicoctl ipam release` go through the same
entry points.

`AffinityType` defaults to `"host"` on read for pre-existing rows that lack the field. `"virtual"` is LoadBalancer affinity. See https://github.com/projectcalico/calico/pull/11179
- crash from assuming the field was always populated.

**Review notes**

- Two-phase `pending → confirmed` is intentional - it's what makes claim races resolvable. Don't optimize it away.
- Treat `pending` affinities as if absent. https://github.com/projectcalico/calico/pull/6003, https://github.com/projectcalico/calico/issues/1712.
- Pre-existing rows lack `AffinityType`; default to `"host"` on read.
- The state machine is library-enforced, not CRD-enforced. New transitions must go through `ipam_block_reader_writer.go`, not a direct `Update`.

## IPAMHandle

The secondary index keyed by handle ID. Lets `ReleaseByHandle` and `IPsByHandle` answer "which allocations belong to this handle?" without scanning every block. Scan is O(blocks);
handle lookup is O(1).

Also enforces per-handle allocation caps for KubeVirt VM persistence: a live-migrating VM reuses the same handle ID across nodes, and the cap stops a buggy caller from piling
allocations onto the same handle.

Handle ID format conventions live in [`ipam-core-library.md`](./ipam-core-library.md#handle-ids).

`Watch` is not supported - [`ipam_handle.go`](../../libcalico-go/lib/backend/k8s/resources/ipam_handle.go) returns `ErrorOperationNotSupported`. kube-controllers reconciles via
the block syncer plus a handle-side scan rather than a watch. See https://github.com/projectcalico/calico/pull/12713.

**Review notes**

- Don't derive handle membership by scanning blocks. The `IPAMHandle` row is the index; bypassing it loses the per-handle cap.
- No watch. New "react to handle changes" features need a syncer-side cache or a periodic scan.
- Don't raise per-handle caps to "fix" a KubeVirt issue without understanding why the cap exists.

## IPAMConfig and IPReservation

Both stored as CRDs alongside the other IPAM resources. [`ipam_config.go`](../../libcalico-go/lib/backend/k8s/resources/ipam_config.go) wraps the singleton `IPAMConfig`. Storage
shape only - field semantics, defaults, and `StrictAffinity` / `MaxBlocksPerHost` / `AutoAllocateBlocks` interactions live in
[`ipam-core-library.md`](./ipam-core-library.md#ipamconfig). `IPReservation` is read at allocation time and converted into an ordinal filter; never participates in CAS.

**Review notes**

- Storage shape only. Semantic changes go in `ipam-core-library.md`.
- New required fields need a default plus heal-forward. Don't add a field that crashes when absent on upgrade.

## CIDR-to-name encoding

Block and `BlockAffinity` CRD names encode the CIDR with dots/colons/slash replaced by `-` (see [`libcalico-go/lib/names/cidr.go`](../../libcalico-go/lib/names/cidr.go)). Two
design points: the encoding is one-way load-bearing - changing it strands every existing row, since lookup by the new name finds nothing and there is no migration path - and the
resulting name is not a stable host identifier, because `BlockAffinity` names exceed 253 chars on long hostnames and get truncated + SHA256-suffixed.

**Review notes**

- Don't change the encoding. Any change strands existing rows; there is no migration path.
- Use the hashed-hostname label for host-scoped lookups, not the parsed CRD name.

## Sequence numbers

The CAS-coordination contract has two halves: the library bumps and checks; the datastore stores. Library side is in
[`ipam-core-library.md`](./ipam-core-library.md#cas-retry-and-sequence-numbers).

Stored on every `IPAMBlock`:

- `SequenceNumber uint64` - block-level counter. Bumped by `updateBlock` before every persist.
- `SequenceNumberForAllocation map[string]uint64` - key is ordinal-as-string, value is the block's `SequenceNumber` at the moment that ordinal was allocated.

The per-ordinal map is what makes ABA detection possible: ordinal allocated to pod A → pod A deleted → ordinal reallocated to pod B → stale release op for pod A → stored
per-ordinal sequence is pod B's, not pod A's → mismatch → release rejected → pod B keeps its IP. The block counter alone can't distinguish "released the same allocation
twice" from "released a stale generation".

Sequence numbers live in the `Spec`, so they survive soft delete and object rename.

**Review notes**

- Older blocks may not have per-ordinal sequence numbers. New release paths must tolerate the absent case, not crash.
- `SequenceNumber` only ever goes up. Don't reset on retry; a reset reopens the ABA window.
- https://github.com/projectcalico/calico/pull/12508 / https://github.com/projectcalico/calico/pull/12555: clearing attributes on sequence-number mismatch without restoring the
  ordinal left the block inconsistent. Skip the allocation entirely on mismatch.

## Soft vs hard delete

Kubernetes has no compare-and-delete by resource version. KDD works around this with a two-step pattern in
[`ipam_block.go`](../../libcalico-go/lib/backend/k8s/resources/ipam_block.go), mirrored in the affinity and handle wrappers:

1. **Soft delete** - `Update` with `Spec.Deleted = true`. CAS on revision succeeds only if no other writer modified the row. This is the linearisation point.
2. **Hard delete** - `Delete` by revision and UID. The K8s row goes away.

Guarantees:

- After step 1 returns success: a *filtering* reader sees the row as absent on any subsequent read. Step 1's CAS is what serializes against concurrent writers.
- After step 2: the row is gone; watch consumers see a delete event.
- Between steps: the row physically exists with `Deleted=true`. **Readers must filter `Deleted=true` client-side.** A reader that skips the filter sees stale rows and races the
  hard delete.

`Deleted` is stored as `bool` in v3 CRDs and as string `"true"` / `"false"` in v1; `ConvertFromK8s` in
[`ipam_affinity_v3.go`](../../libcalico-go/lib/backend/k8s/resources/ipam_affinity_v3.go) normalizes.

**Review notes**

- New readers must filter `Deleted=true` client-side. Missing this is the bug class behind https://github.com/projectcalico/calico/pull/10855.
- The two-step is intentional. Don't replace it with a bare `Delete` to "simplify" - you lose CAS on the delete and races return.
- The hard delete's CAS uses the soft-deleted row's UID. Don't drop UID from the delete call.

## Host-scoped lookups

KDD has no prefix-key matching. Any "list X for host Y" lookup must use a hashed-hostname label set by `UpgradeHost()`, called from CNI startup, calico-node startup, and
kube-controllers startup. A new label-dependent query that bypasses `UpgradeHost()` leaves pre-upgrade rows invisible. See https://github.com/projectcalico/calico/pull/10855.

**Review notes**

- A new label-dependent query needs the label stamped at every startup path. `UpgradeHost()` is the chokepoint; don't add a query that bypasses it.
- Don't rely on key-prefix matching to scope reads to a host. KDD doesn't support it; use the hashed-hostname label.
- Pre-upgrade rows are invisible to label queries until `UpgradeHost()` has run. Reconciliation that assumes the label is always present will miss them.

## crd.projectcalico.org/v1 vs projectcalico.org/v3

IPAM CRDs exist on both `crd.projectcalico.org/v1` (internal) and `projectcalico.org/v3` (public). The two groups are not symmetric: v1 carries the storage shape every IPAM caller
has used since the beginning, while v3 exposes a user-facing surface with a different name (`IPAMConfiguration` vs `IPAMConfig`) and stricter field validation.

The full design of the CRD-group layout is owed its own doc; this section covers only the bits relevant to a reviewer touching the backend wrappers.

- Backend wrappers under `libcalico-go/lib/backend/k8s/resources/` speak v1. Conversion lives in `ipam_*_v1.go` / `ipam_*_v3.go`.
- The library and `calicoctl` consume the wrapped types. New code outside the backend wrappers should not import v1 types - the `lib/v3` → `lib/internalapi` rename
  (https://github.com/projectcalico/calico/pull/11870) keeps that boundary clean.
- Adding a field to v1 doesn't make it reachable through v3 or the operator until the v3 type, conversion, and operator reconciler are updated too. A v1-only field is invisible to
  end-user kubectl access against the v3 group.

**Review notes**

- Don't leak `crd.projectcalico.org/v1` types through new public APIs.
- A new `IPAMConfig` / `IPAMConfiguration` field needs the v3 type and conversion updated, not just v1. Operator RBAC and reconciliation usually need to follow -
  https://github.com/tigera/operator/pull/4775, https://github.com/tigera/operator/pull/4776.
- Until the dedicated CRD-group design lands, verify cross-group assumptions in code rather than inferring from this doc.

## Keep in sync with

- [`./ipam-core-library.md`](./ipam-core-library.md) - paired. CAS retry, sequence-number checking, handle-ID conventions, and `IPAMConfig` semantics live there.
- [`./ipam-gc.md`](./ipam-gc.md) - the GC depends on the `BlockAffinity` state machine and the soft-delete contract.
