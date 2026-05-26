<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM core library

This sub-design covers the core IPAM library in
`libcalico-go/lib/ipam/`. It is the in-process API every IPAM caller
goes through (CNI plugin, kube-controllers, `node`, `calicoctl`,
operator). The cross-component picture - data model, consumers, repo
split - lives in the [index](./DESIGN.md).

## Public API surface

The library's contract is defined by `Interface` in
[`interface.go`](../../../libcalico-go/lib/ipam/interface.go). The
methods callers actually reach for:

| Method | Purpose |
|---|---|
| `AutoAssign` | Allocate N IPs for a host. Honours pool selectors, host affinity, `StrictAffinity`, `MaxBlocksPerHost`, and per-handle caps. Returns block-masked CIDRs (not /32) so callers can program routes for the surrounding block. |
| `AssignIP` | Allocate a specific IP. Used by tunnel-address allocators and LoadBalancer IPAM. |
| `ReleaseIPs` | Release IPs by `ReleaseOptions{Address, Handle, SequenceNumber}`. Returns already-free IPs plus IPs skipped on sequence-number mismatch. |
| `ReleaseByHandle` | Release every IP attached to a handle ID. Used on CNI DEL and tunnel teardown. |
| `GetAssignmentAttributes` | Read the per-allocation attribute map for an IP. Used by the GC for leak validation. |
| `IPsByHandle` | Reverse-lookup IPs from a handle ID without scanning blocks. |
| `ClaimAffinity` / `ReleaseHostAffinities` | Manage per-host block affinities directly. Used by the GC and `calicoctl ipam release`. |
| `GetIPAMConfig` / `SetIPAMConfig` | Read/write the `IPAMConfig` singleton. Operator owns writes in production. |
| `SetOwnerAttributes` | KubeVirt-only. Swap owner attributes on an existing allocation under preconditions, without releasing and re-allocating. |

There is no `AssignFixedIP` - the API is `AssignIP`. The source of
truth for signatures is the interface definition.

**Review notes**

- New CRDs / new API methods need operator RBAC; see https://github.com/tigera/operator/pull/4775 (May 2026). Easy to miss on backports.
- Don't leak `crd.projectcalico.org/v1` types through new public APIs. The `lib/v3` -> `lib/internalapi` rename (https://github.com/projectcalico/calico/pull/11870) exists to keep that boundary clean.
- `AutoAssign` returning block-masked CIDRs is load-bearing for the CNI plugin's routing. Don't quietly switch to /32.

## AutoAssign and host affinity

`AutoAssign` is the hot path. Entry point is `autoAssign` in
[`ipam.go`](../../../libcalico-go/lib/ipam/ipam.go). The walk:

1. Resolve hostname (arg wins, else `os.Hostname()`). Load `IPReservation` CRDs into a filter.
2. `prepareAffinityBlocksForHost`: get the node, resolve pools via `determinePools` (node selector + namespace selector + version + block-size validity all gate access), list existing `BlockAffinity` rows for this host.
3. Compute the block cap: min of global `MaxBlocksPerHost` and request-level, defaulting to 20 if both are 0. Once `numBlocksOwned` reaches the cap, `allowNewClaim` is forced false.
4. Walk affine blocks via `findOrClaimBlock`. Each block is fetched via `queryAffinity` + `getBlockFromAffinity`, which creates the block if the affinity exists but the block doesn't (recovery path for a node that crashed mid-claim).
5. If existing affine blocks are exhausted and `allowNewClaim=true`, `findUsableBlock` searches for an unclaimed block in the pool, or reclaims an empty affine block older than `EmptyBlockMinReclaimAge` (1 minute). Claim is two-phase: `getPendingAffinity` creates the `BlockAffinity` in `pending`, `claimAffineBlock` creates the `IPAMBlock` and transitions the affinity to `confirmed`.
6. If `StrictAffinity=false` and the request still isn't satisfied, fall back to non-affine blocks via `randomBlockGenerator`. The generator seeds its RNG from the hostname hash so retries hit the same blocks in the same order, reducing thrash between competing hosts.

`StrictAffinity=true` (Windows always, or operator-configured
elsewhere) suppresses the non-affine fallback. `MaxBlocksPerHost`
suppresses new-block claims but not allocation from existing affine
blocks; a node that's already at the cap can still fill the blocks
it owns.

**Review notes**

- The `pending -> confirmed` two-phase claim is intentional; don't "optimise" it away. It's what makes claim races resolvable. See https://github.com/projectcalico/calico/pull/6003, https://github.com/projectcalico/calico/pull/1712.
- Treat pending block affinities as if absent when deciding ownership or advertising routes.
- Pre-existing blocks may lack `AffinityType`; default to `"host"` on read. https://github.com/projectcalico/calico/pull/11179 was a crash from this assumption.
- Pool resolution is in the hot path. `ResolvePools` was hand-optimised in https://github.com/projectcalico/calico/pull/9891 - preserve the fast path.
- `MaxBlocksPerHost` defaults are a recurring doc/code drift point (https://github.com/projectcalico/calico/issues/9462). If you change the default in code, update the docs in the same PR.

## CAS retry and sequence numbers

All `IPAMBlock`, `BlockAffinity`, and `IPAMHandle` updates are CAS
on resource version via `backend.Client.Update`. The library wraps
every write in a bounded retry loop (`datastoreRetries = 100`,
declared in [`ipam.go`](../../../libcalico-go/lib/ipam/ipam.go)).
On `ErrorResourceUpdateConflict` the loop re-fetches and retries;
on any other error it exits immediately and surfaces to the caller.

Each `IPAMBlock` carries a `SequenceNumber` that
[`updateBlock`](../../../libcalico-go/lib/ipam/ipam_block_reader_writer.go)
increments on every write, and per-ordinal
`SequenceNumberForAllocation[ord]` records the block's sequence
number at allocation time. A `ReleaseOptions.SequenceNumber` from
the caller is compared against the stored value; on mismatch the
library returns `ErrorBadSequenceNumber` and the IP is **not**
released. This prevents the GC from freeing an ordinal that was
reallocated to a new pod between scan and release - the new pod's
allocation bumps the block sequence number, so stale release
options won't match.

Block release is parallelised per block via a semaphore sized at
`GOMAXPROCS`.

**Review notes**

- Every release path must plumb the sequence number through. A release path that drops it on the floor is a regression. See `ReleaseOptions.SequenceNumber`.
- Don't mutate the in-memory `*model.AllocationBlock` (KVPair) before persisting. Update the value, call `updateBlock`, then update auxiliary state (handle, host info). https://github.com/projectcalico/calico/pull/12697 was exactly this bug: partial mutation persisted via a retry loop after the actual write was skipped.
- The `Deallocated` / `Unallocated` queue cycling is load-bearing for IP-reuse delay. New code that punches the bitmap directly skipping the queue breaks rate-limited reuse (relevant to https://github.com/projectcalico/calico/issues/12638).
- Older blocks may not have per-ordinal sequence numbers. New code must tolerate the absent case (default + heal-forward), not crash.

## Handle IDs

A handle ID is an opaque string from the library's point of view,
but its **format is a convention every IPAM caller has to follow**
because the GC and `calicoctl ipam check` parse handle prefixes to
classify allocations.

Conventions in use:

| Caller | Handle ID format |
|---|---|
| CNI workload (default) | `<network-name>.<container-id>` via `cni-plugin/internal/pkg/utils.GetHandleID`. For the default network, `<network-name>` is `k8s-pod-network`. |
| CNI workload (KubeVirt persistent) | `<network-name>.<namespace>-<vm-name>` so live-migrated VMs keep the same handle. |
| IPIP tunnel | `ipip-tunnel-addr-<node>` |
| VXLAN tunnel | `vxlan-tunnel-addr-<node>` (IPv6 suffixed `-ipv6`) |
| WireGuard tunnel | `wireguard-tunnel-addr-<node>` (IPv6 suffixed `-ipv6`) |
| Windows-reserved | literal `windows-reserved-ipam-handle` |
| LoadBalancer | `<namespace>:<service>` |

The CNI plugin also keeps a separate **workload-ID** form
(`<namespace>.<pod>`) and releases by both on DEL so that
allocations made before a CRI container-ID change can still be
found - see [`./ipam-cni.md`](./ipam-cni.md).

**Review notes**

- Changing a handle format without updating the GC and `calicoctl ipam check` parsers will leak. Tunnel prefixes (`ipip-tunnel-addr-`, `vxlan-tunnel-addr-`, `wireguard-tunnel-addr-`) are pattern-matched at multiple sites.
- A new handle prefix needs migration code in `calicoctl ipam migrate` - tunnel-type handles are remapped during node renames.
- Skipping the workload-ID release on CNI DEL leaks IPs whose container-ID changed under CRI. Don't drop the second release call.

## IPAMConfig

`IPAMConfig` is a singleton CR. Defaults are applied on read by
`GetIPAMConfig` when the CR is missing, so callers can rely on
"there is always a config". Operator owns the write path in
production; `SetIPAMConfig` validates:

- `StrictAffinity=false` + `AutoAllocateBlocks=false` is rejected (would mean "never allocate anywhere", which is never what the user wants).
- `MaxBlocksPerHost > 0` requires `StrictAffinity=true`.

Fields:

| Field | Effect |
|---|---|
| `StrictAffinity` | Disables non-affine fallback in `AutoAssign`. Windows nodes force this to true regardless of the stored value because Windows can't route /26 affinity blocks remotely. |
| `MaxBlocksPerHost` | Per-host cap on the number of affine blocks. 0 means default (20). Once a host hits the cap, `allowNewClaim` is forced false; existing blocks still fill. |
| `AutoAllocateBlocks` | When false, `AutoAssign` will never claim a new block - only allocate from blocks the host already owns. |
| `KubeVirtVMAddressPersistence` | Default for whether KubeVirt VM addresses survive VM restart / migration. Auto-detection is on by default. |

**Review notes**

- The default-when-missing behaviour is load-bearing. New required fields need a default plus heal-forward; don't add a field that crashes when absent.
- `MaxBlocksPerHost > 0` only makes sense with `StrictAffinity=true`; the validator enforces this. If you relax the validator, you also need to define what "borrow blocks but cap our own" means - it currently isn't defined.
- Operator owns `SetIPAMConfig` in production. New fields surface through the operator API too, or they're not usable.

## Error taxonomy

Sentinel errors live in
[`ipam_errors.go`](../../../libcalico-go/lib/ipam/ipam_errors.go)
and at the top of `ipam.go`. The ones callers care about:

| Error | Source | Who handles it |
|---|---|---|
| `ErrBlockLimit` | `autoAssign` when `numBlocksOwned >= MaxBlocksPerHost` | CNI plugin (surfaces to kubelet); user-visible. |
| `ErrNoQualifiedPool` | `determinePools` when no pool matches selectors / version / intended use | CNI plugin; user-visible. |
| `ErrStrictAffinity` | `SetIPAMConfig` when a Windows config sets `StrictAffinity=false` explicitly | Operator / `calicoctl`. |
| `IPAMConfigConflictError` | `SetIPAMConfig` validation | Operator. |
| `noFreeBlocksError` | Internal to the claim loop | `autoAssign` translates to `ErrBlockLimit` or surfaces via the retry loop. |
| `errBlockClaimConflict` | Another host won the race for a block | Retry loop swallows. |
| `errBlockNotEmpty` | `ReleaseBlockAffinity(mustBeEmpty=true)` against a block that still has allocations | GC; this is a precondition violation, not a transient. |
| `errStaleAffinity` | `BlockAffinity` exists but the block's `Affinity` field disagrees | Retry loop in `findOrClaimBlock`. |
| `ErrorResourceUpdateConflict` | CAS revision mismatch | Retry loop. |
| `ErrorBadSequenceNumber` | Stored sequence number disagrees with `ReleaseOptions.SequenceNumber` | GC; record as "skipped" and re-evaluate next pass. |

**Review notes**

- `mustBeEmpty=true` on `ReleaseBlockAffinity` is a hard precondition. The caller verifies emptiness; the GC's two-consecutive-empty-observations check is what gates this.
- A new release code path that catches `ErrorBadSequenceNumber` and proceeds anyway defeats the protocol. The right behaviour is to skip and re-evaluate.
- Internal sentinel errors (`noFreeBlocksError`, `errBlockClaimConflict`, `errStaleAffinity`) are not part of the public API. Don't return them to callers; translate to the exported `Err*` values.

## Keep in sync with

- [`./ipam-datastore.md`](./ipam-datastore.md) - the CAS protocol and sequence-number scheme are defined together with the backend.
- [`./ipam-cni.md`](./ipam-cni.md) - the CNI plugin duplicates the handle-ID convention; changes here that affect the format need to land there too.
- [`../../../libcalico-go/lib/ipam/`](../../../libcalico-go/lib/ipam/) - a `DESIGN.md` stub in that directory points back here.
