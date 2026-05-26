<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM - Architecture & Design Index

Calico's IPAM is the subsystem that allocates pod, tunnel, and
LoadBalancer IPs out of configured IP pools. It is not owned by any
single component: the core library lives in `libcalico-go/lib/ipam`,
but it's invoked from `cni-plugin`, `kube-controllers`, `node`,
`calicoctl`, and (read-only) from Felix. The design lives at
`docs/design/ipam/` rather than under any one component for the same
reason.

## 1. Architecture overview

### Data model

IPAM state is stored as four CRDs under `crd.projectcalico.org/v1`,
plus `IPReservation` for carve-outs:

| Resource | Role |
|---|---|
| `IPAMBlock` | Contiguous slice of a pool (default /26 IPv4, /122 IPv6). Holds the ordinal bitmap, per-allocation attributes, and per-ordinal sequence numbers. |
| `BlockAffinity` | Per-host (or per-virtual-owner) claim on a block. State machine: `pending` -> `confirmed` -> `pendingDeletion`. |
| `IPAMHandle` | Secondary index keyed by handle ID, so `ReleaseByHandle` doesn't scan blocks. Also enforces per-handle allocation caps (KubeVirt VM persistence). |
| `IPAMConfig` | Singleton. Holds `StrictAffinity`, `MaxBlocksPerHost`, `AutoAllocateBlocks`, `KubeVirtVMAddressPersistence`. |
| `IPReservation` | Carve-outs from the pool (tunnel addresses, externally-managed IPs). Filtered at block-skip and ordinal-skip granularity. |

These resources still live on the internal `crd.projectcalico.org/v1`
group rather than the public `projectcalico.org/v3`. The long-running
discussion about promoting them is
https://github.com/projectcalico/calico/issues/6412.

### Why blocks, and why per-host affinity

**Blocks** exist to amortise the datastore round-trip cost. Allocating
one IP per pod against a cluster-wide bitmap would put every pod
creation on the same CAS contention point. A block batches a /26 of
ordinals into a single object, so most allocations are CAS on one
object owned by one node. Blocks also let the dataplane advertise one
route per block, not one per pod.

**Per-host affinity** turns cluster-wide CAS thrash into per-node CAS.
A node owns its blocks; allocations are local writes. When a node
runs out of affine blocks it can borrow ordinals from another node's
block (unless `StrictAffinity=true`, which is required when IPs are
statically routed per-node by downstream gear and borrowing would
break routing). Windows nodes force `StrictAffinity=true` because
Windows can't route /26 affinity blocks remotely.

### The three primary consumers

| Consumer | Path | Role |
|---|---|---|
| CNI plugin | `cni-plugin/pkg/ipamplugin/`, `node/cmd/calico-ipam/` | Pod ADD/DEL. Hot path; latency-sensitive. |
| Garbage collector | `kube-controllers/pkg/controllers/node/` | Leak detection, handle reconciliation, empty-block release. |
| Tunnel-address allocator | `node/pkg/allocateip/` | IPIP / VXLAN / Wireguard node tunnel addresses. |

The IPAM GC lives in the *node* controller
(`kube-controllers/pkg/controllers/node`), not in
`pkg/controllers/ipam`. Confusing, but historical and not worth
moving.

### Repo split

- `projectcalico/calico` (OSS) - all the IPAM code described here.
- `tigera/operator` - owns the `IPAMConfig` CR (reconciles it against
  user-facing operator config) and the RBAC for the IPAM CRDs.
  Operator can refuse to apply config changes when datastore state
  looks corrupt.
- `tigera/calico-private` (enterprise) - carries the L2 bridge /
  VLAN, federation, and KubeVirt IPAM extensions. Mostly cherry-picks
  from OSS; the core library lives upstream.

## 2. Sub-design index

Per-topic design docs in this directory. A PR that touches files
across multiple `applies to` scopes must load every matching
sub-design.

| Topic | Applies to | Status |
|---|---|---|
| [ipam-core-library](./ipam-core-library.md) | `libcalico-go/lib/ipam/**` (excluding `vmipam/`) | ✅ exists |
| [ipam-datastore](./ipam-datastore.md) | `libcalico-go/lib/backend/**/ipam*`, `libcalico-go/lib/backend/**/block_affinity*` | ✅ exists |
| [ipam-cni](./ipam-cni.md) | `cni-plugin/pkg/ipamplugin/**`, `node/cmd/calico-ipam/**` | ✅ exists |
| [ipam-gc](./ipam-gc.md) | `kube-controllers/pkg/controllers/node/ipam*.go`, `kube-controllers/pkg/controllers/node/pool_manager.go`, `kube-controllers/pkg/controllers/node/ipam_allocation.go` | ✅ exists |
| [ipam-other-callers](./ipam-other-callers.md) | `node/pkg/allocateip/**`, `calicoctl/calicoctl/commands/ipam/**`, `libcalico-go/lib/ipam/vmipam/**`, Felix IPAM read paths | ✅ exists |

A missing sub-design means the area's invariants have not been
written down yet - not that the area has no constraints. Treat
absence as "read the code and ask"; don't assume anything goes.

## 3. For coding agents and reviewers

- **Follow links.** Sub-designs reference sibling sub-designs,
  `.github/instructions/*.instructions.md` files, code, and
  external references. Load them.
- **Load what applies - by path or by topic.** The `applies to`
  globs above are the path-based trigger: a PR that touches both
  the core library and CNI plugin code needs both sub-designs. The
  topic of the change matters too - a PR described as "fix the GC
  leak handler" should pull `ipam-gc.md` even if the edit happens
  to land in a shared helper that the glob doesn't list narrowly.
  When in doubt, pull the topic-relevant sub-design.
- **Review notes are the checklist.** Each sub-design embeds
  per-section review notes describing the invariants a PR must
  respect. At write-time, respect them; at review-time, apply
  them.
- **Update rule.** A change to how IPAM works in a given area
  must update the relevant sub-design in this directory in the
  same PR. This index is also updated when the sub-design table,
  an `applies to` scope, or §1's architecture overview changes.
  Exemptions: (a) a bug fix that restores behaviour the doc
  already describes, (b) a mechanical refactor with no observable
  change, (c) comment or log-message edits, (d) dependency bumps.
  If in doubt, update. The path-scoped
  [`.github/instructions/ipam.instructions.md`](../../../.github/instructions/ipam.instructions.md)
  file wires this rule into Copilot's automated review.

## 4. Adding a new sub-design

When a new IPAM topic earns its own doc:

1. Create `docs/design/ipam/<topic>.md`. Follow the shape of an
   existing sub-design: narrative prose, architecture, per-section
   review notes at the end of each section, and a "keep this in
   sync" tail.
2. Update the sub-design index above with a row giving the link,
   the `applies to` glob, and the ✅ exists marker.
3. Move any orientation content that belongs to the new sub-design
   out of this file into the new doc (most of §1 is cross-cutting
   and stays here).
4. Create a matching
   `.github/instructions/ipam-<topic>.instructions.md` with the
   `applyTo` globs from the table above plus a pointer to the new
   design doc. Keep it thin.
