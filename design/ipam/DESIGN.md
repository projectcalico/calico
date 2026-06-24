<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM - Architecture & Design Index

Calico's IPAM is the subsystem that allocates pod, tunnel, and LoadBalancer IPs out of configured IP pools. It is not owned by any single component: the core library lives in
`libcalico-go/lib/ipam`, but it's invoked from `cni-plugin`, `kube-controllers`, `node`, `calicoctl`, and (read-only) from Felix. The design lives at `design/ipam/` rather
than under any one component for the same reason.

## 1. Architecture overview

### Data model

IPAM state is stored as four CRDs, plus `IPReservation` for carve-outs:

| Resource | Role |
|---|---|
| `IPAMBlock` | Contiguous slice of a pool (default /26 IPv4, /122 IPv6). Holds the ordinal bitmap, per-allocation attributes, and per-ordinal sequence numbers. |
| `BlockAffinity` | Per-host (or per-virtual-owner) claim on a block. State machine: `pending` -> `confirmed` -> `pendingDeletion`. |
| `IPAMHandle` | Secondary index keyed by handle ID, so `ReleaseByHandle` doesn't scan blocks. Also enforces per-handle allocation caps (KubeVirt VM persistence). |
| `IPAMConfig` / `IPAMConfiguration` | Singleton. Holds `StrictAffinity`, `MaxBlocksPerHost`, `AutoAllocateBlocks`, `KubeVirtVMAddressPersistence`. The v1 name is `IPAMConfig`; the v3 name is `IPAMConfiguration`. |
| `IPReservation` | Carve-outs from the pool (tunnel addresses, externally-managed IPs). Filtered at block-skip and ordinal-skip granularity. |

The IPAM CRDs exist on both `crd.projectcalico.org/v1` and `projectcalico.org/v3`. The two groups are not symmetric - they differ in field shape, naming (`IPAMConfig` vs
`IPAMConfiguration`), and which clients write through each. A separate design doc covering the CRD-group layout is owed; until it lands, treat any cross-group assumption as
something to verify in code rather than infer from this doc. The promotion history is https://github.com/projectcalico/calico/issues/6412.

### Why blocks, and why per-host affinity

**Blocks** exist to amortize the datastore round-trip cost. Allocating one IP per pod against a cluster-wide bitmap would put every pod creation on the same CAS contention point. A
block batches a /26 of ordinals into a single object, so most allocations are CAS on one object owned by one node. Blocks also let the dataplane advertise one route per block, not
one per pod.

**Per-host affinity** turns cluster-wide CAS thrash into per-node CAS. A node owns its blocks; allocations are local writes. When a node runs out of affine blocks it can borrow
ordinals from another node's block, unless `StrictAffinity=true`. Strict affinity is the mode for clusters where downstream routing is per-node and borrowing would strand traffic
(Windows forces this; see [ipam-cni](./ipam-cni.md#platform-differences)).

### The three primary consumers

| Consumer | Path | Role |
|---|---|---|
| CNI plugin | `cni-plugin/pkg/ipamplugin/`, `node/cmd/calico-ipam/` | Pod ADD/DEL. Hot path; latency-sensitive. |
| Garbage collector | `kube-controllers/pkg/controllers/node/` | Leak detection, handle reconciliation, empty-block release. |
| Tunnel-address allocator | `node/pkg/allocateip/` | IPIP / VXLAN / WireGuard node tunnel addresses. |

The IPAM GC lives in the *node* controller (`kube-controllers/pkg/controllers/node`), not in `pkg/controllers/ipam`. Confusing, but historical and not worth moving.

### Repo split

- `projectcalico/calico` (OSS) - all the IPAM code described here.
- `tigera/operator` - reconciles `IPAMConfig` / `IPAMConfiguration` against user-facing operator config and provisions RBAC for the IPAM CRDs. End users can also edit the config CR
  directly (name varies by API group); operator is one writer, not the only one.

## 2. Sub-design index

Per-topic design docs in this directory. A PR that touches files across multiple `applies to` scopes must load every matching sub-design.

| Topic | Applies to | Status |
|---|---|---|
| [ipam-core-library](./ipam-core-library.md) | `libcalico-go/lib/ipam/**` (excluding `vmipam/`) | ✅ exists |
| [ipam-datastore](./ipam-datastore.md) | `libcalico-go/lib/backend/**/ipam*`, `libcalico-go/lib/backend/**/block_affinity*` | ✅ exists |
| [ipam-cni](./ipam-cni.md) | `cni-plugin/pkg/ipamplugin/**`, `cni-plugin/pkg/k8s/**`, `node/cmd/calico-ipam/**` | ✅ exists |
| [ipam-gc](./ipam-gc.md) | `kube-controllers/pkg/controllers/node/ipam*.go`, `kube-controllers/pkg/controllers/node/pool_manager.go`, `kube-controllers/pkg/controllers/node/ipam_allocation.go` | ✅ exists |
| [ipam-other-callers](./ipam-other-callers.md) | `node/pkg/allocateip/**`, `calicoctl/calicoctl/commands/ipam/**`, `calicoctl/calicoctl/commands/datastore/migrate/**`, `kube-controllers/pkg/controllers/loadbalancer/**`, `kube-controllers/pkg/controllers/flannelmigration/**`, `libcalico-go/lib/ipam/vmipam/**`, Felix IPAM read paths | ✅ exists |

A missing sub-design means the area's invariants have not been written down yet - not that the area has no constraints. Treat absence as "read the code and ask"; don't assume
anything goes.

## 3. For coding agents and reviewers

- **Follow links.** Sub-designs reference sibling sub-designs, `.github/instructions/*.instructions.md` files, code, and external references. Load them.
- **Load what applies - by path or by topic.** The `applies to` globs above are the path-based trigger: a PR that touches both the core library and CNI plugin code needs both
  sub-designs. The topic of the change matters too - a PR described as "fix the GC leak handler" should pull `ipam-gc.md` even if the edit happens to land in a shared helper that
  the glob doesn't list narrowly. When in doubt, pull the topic-relevant sub-design.
- **Review notes are the checklist.** Each sub-design embeds per-section review notes describing the invariants a PR must respect. At write-time, respect them; at review-time,
  apply them.
- **Update rule.** A change to how IPAM works in a given area must update the relevant sub-design in this directory in the same PR. This index is also updated when the
  sub-design table, an `applies to` scope, or §1's architecture overview changes. Exemptions: (a) a bug fix that restores behavior the doc already describes, (b) a mechanical
  refactor with no observable change, (c) comment or log-message edits, (d) dependency bumps. If in doubt, update. The path-scoped
  [`.github/instructions/ipam.instructions.md`](../../.github/instructions/ipam.instructions.md) file wires this rule into Copilot's automated review.

## 4. Cross-cutting review rubric

The questions below are the ones that have caught real regressions across the IPAM subsystem. A reviewer (or an agent opening a PR) should be able to answer "yes" or "n/a" to each.
"Didn't check" is a request for changes.

1. **Sequence-number protection on every release path.** Does the change plumb `ReleaseOptions.SequenceNumber` through any new release code? Dropping it reopens the
   pod-reuse-between-scan-and-release window. See [ipam-core-library §CAS retry and sequence numbers](./ipam-core-library.md#cas-retry-and-sequence-numbers).
2. **kube-controllers state-map updates touch every map.** `allBlocks`, `allocationsByBlock`, `allocationState`, `handleTracker`, `confirmedLeaks`, `nodesByBlock`, `blocksByNode`,
   `emptyBlocks`. A new mutation path that updates one but not the others is the v3.32 memory-leak pattern. See [ipam-gc §Testing](./ipam-gc.md#testing-the-gc).
3. **All-or-none per handle on release.** If one IP on a handle is still valid, the entire handle is skipped. Auxiliary-state reconcilers must respect this too. See [ipam-gc
   §Handle reconciliation](./ipam-gc.md#handle-reconciliation).
4. **KDD lookups go through labels, not client-side filters.** A new "list X for host Y" query needs the hashed-hostname label stamped by `UpgradeHost()`. See [ipam-datastore
   §Host-scoped lookups](./ipam-datastore.md#host-scoped-lookups).
5. **In-memory block consistent with what's persisted.** A change that mutates the `*model.AllocationBlock` KVPair before `updateBlock` returns success can persist partial state
   via the retry loop. See [ipam-core-library §CAS retry and sequence numbers](./ipam-core-library.md#cas-retry-and-sequence-numbers).
6. **Handle-format change updated everywhere it's parsed.** Tunnel handle prefixes are parsed by `calicoctl datastore migrate` (which rewrites them on node rename) - and its prefix
   list is v4-only today, so it already misses the `*-v6-tunnel-addr-` handles. The GC and `calicoctl ipam check` don't parse the prefix: the GC classifies by `AttributeType`, and
   `ipam check` reads tunnel IPs off the `Node` spec. A new tunnel handle type therefore needs both an `AttributeType` and a migrate-prefix entry. See [ipam-core-library §Handle
   IDs](./ipam-core-library.md#handle-ids).
7. **Operator-side change for new CRDs or RBAC verbs.** A new IPAM CRD or a new verb on an existing one needs a paired `tigera/operator` PR or GC paths fail closed. See
   [ipam-datastore §crd.projectcalico.org/v1 vs projectcalico.org/v3](./ipam-datastore.md#crdprojectcalicoorgv1-vs-projectcalicoorgv3).
8. **Upgrade path for pre-existing data.** Existing rows may lack a new field (`AffinityType`, per-ordinal sequence number, tunnel handle prefix). Code that assumes the field is
   present must instead default + heal-forward.

A PR that answers "no" to any of these without a written reason should not merge.

## 5. Adding a new sub-design

When a new IPAM topic earns its own doc:

1. Create `design/ipam/<topic>.md`. Follow the shape of an existing sub-design: narrative prose, architecture, per-section review notes at the end of each section, and a "keep
   this in sync" tail.
2. Update the sub-design index above with a row giving the link, the `applies to` glob, and the ✅ exists marker.
3. Move any orientation content that belongs to the new sub-design out of this file into the new doc (most of §1 is cross-cutting and stays here).
4. Create a matching `.github/instructions/ipam-<topic>.instructions.md` with the `applyTo` globs from the table above plus a pointer to the new design doc. Keep it thin.
