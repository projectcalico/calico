<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM: other callers

Catch-all for IPAM callers that aren't covered by the four primary sub-designs ([core library](./ipam-core-library.md), [datastore](./ipam-datastore.md), [CNI](./ipam-cni.md),
[GC](./ipam-gc.md)). Each section here is intentionally shallow - just enough to point at the right code and call out the handle convention or invariant a reviewer needs to know.
If a caller grows enough complexity to warrant its own sub-design, lift it out of this file.

The unifying thread: every caller uses a distinct handle convention. Don't change a handle format in one place without checking the callers that depend on it - `calicoctl datastore
migrate` parses the tunnel prefixes, and the CNI DEL path releases by both the handle and the workload-ID forms.

## calicoctl

[`calicoctl/calicoctl/commands/ipam/`](../../calicoctl/calicoctl/commands/ipam/) is the operator-facing CRUD surface for IPAM state. `show`, `check`, and `release` are the
IPAM-meaningful subcommands; `configure` and `split` are admin-CRUD on `IPAMConfig` / `IPPool`. The `check` algorithm reuses the validity heuristics the GC applies, but exposed for
manual review without a running controller.

**Review notes**

- New tunnel handle prefixes need to be added to `calicoctl datastore migrate`, which rewrites tunnel handle IDs during node renames.
- `check` and the GC share validity logic. If you change one, check the other doesn't drift.

## Node tunnel-address allocator

[`node/pkg/allocateip/allocateip.go`](../../node/pkg/allocateip/allocateip.go). Runs inside the node container, watches `IPPool` and `FelixConfiguration`, and reconciles tunnel
interface addresses (IPIP, VXLAN, VXLAN-v6, WireGuard, WireGuard-v6). It's wired in from [`node/pkg/node/command.go`](../../node/pkg/node/command.go) as
`newAllocateTunnelAddrsCommand` - not the path `node/pkg/ipam/` that you might guess from grep.

For each tunnel type, per reconcile:

- Tunnel enabled, no address: `AutoAssign` with `Attrs[ipam.AttributeType]` set to the tunnel type and `Hostname` = node name, `IntendedUse = Tunnel`. Handle is
  `<tunnel>-tunnel-addr-<node>` for v4; the v6 variants put `-v6-` in the middle (`vxlan-v6-tunnel-addr-<node>`, `wireguard-v6-tunnel-addr-<node>`), not a suffix.
- Tunnel enabled, address exists: `GetAssignmentAttributes` to validate the address is still in a valid pool. If the pool is gone, `ReleaseByHandle` then reassign.
- Tunnel disabled: `ReleaseByHandle`.

Runs continuously and reacts to syncer updates. Differs from pod IPAM in three ways worth keeping in mind: not tied to a pod lifecycle (only released when the node is gone or the
tunnel is disabled), uses `IntendedUse = Tunnel` so pool selection respects `allowedUses`, and the GC doesn't validate tunnel IPs via pod existence (see [GC](./ipam-gc.md)).

**Review notes**

- Pre-handle tunnel allocations exist on upgraded clusters; the release-by-IP-then-reassign path migrates them. Don't break it.
- The GC recognizes tunnel allocations by `AttributeType`, and `calicoctl ipam check` reads tunnel IPs off the `Node` spec - neither parses the handle prefix. The prefix is parsed
  by `calicoctl datastore migrate`, whose list is v4-only today (`ipip-tunnel-addr-`, `vxlan-tunnel-addr-`, `wireguard-tunnel-addr-`) and so already misses the `*-v6-tunnel-addr-`
  handles. A new tunnel type needs an `AttributeType` and a migrate-prefix entry; if you touch the migrate list, add the v6 prefixes too.

## Felix

Felix doesn't allocate IPs. It holds an IPAM client for one purpose: the KubeVirt live-migration owner-swap monitor in
[`felix/dataplane/linux/live_migration.go`](../../felix/dataplane/linux/live_migration.go).

When a workload endpoint transitions to "active" live-migration state, the monitor calls `vmipam.EnsureActiveVMOwnerAttrs` to promote the alternate owner to active under a
`CompareAndSwap` precondition. This is the dataplane half of the KubeVirt IP persistence handshake described in [`./ipam-cni.md`](./ipam-cni.md). Felix swaps ownership; it never
assigns.

**Review notes**

- Don't introduce a path that mutates owner attrs without going through `vmipam`, or the `CompareAndSwap` precondition protecting against the CNI racing the swap goes away.
- Trigger-path refactors have regressed live-migration more than once; exercise the GARP and syncer paths whenever touching the monitor.

## LoadBalancer controller

[`kube-controllers/pkg/controllers/loadbalancer/`](../../kube-controllers/pkg/controllers/loadbalancer/). Allocates IPs for Calico's Service LoadBalancer abstraction. Uses
`virtual:load-balancer` affinity (not host-anchored), filters pools on `allowedUses: LoadBalancer`, and handles are `lb-<hash>` where `<hash>` is the sha256 of `<service>-<namespace>-<uid>` (see `createHandle`), not the `virtual:load-balancer` affinity string. `AssignIP` for static `loadBalancerIP`,
`AutoAssign` otherwise; `ReleaseByHandle` on delete.

Cold-start races are the recurring failure mode: the controller needs full block context before assigning, or replicas can hand out duplicate IPs.

**Review notes**

- LB pool resolution is its own filter path. If you change `ResolvePools` semantics in libcalico, run the LB controller tests too - it's not just CNI.
- The `virtual:load-balancer` affinity type bypasses the host-affinity GC rules. Tunnel-IP-style "delete when node gone" reasoning doesn't apply here.

## Flannel migration

[`kube-controllers/pkg/controllers/flannelmigration/ipam_migrator.go`](../../kube-controllers/pkg/controllers/flannelmigration/ipam_migrator.go). One-time migration from
Flannel's host-local IPAM to Calico IPAM. For each node:

1. Read Flannel subnet.
2. `ClaimAffinity` for the equivalent Calico block.
3. Reassign the existing VXLAN tunnel address with Calico metadata.

Handle convention for the migrated tunnel: the standard `vxlan-tunnel-addr-<node>`. Idempotent; runs during cluster
upgrade only.

**Review notes**

- The migrator is upgrade-only code. It's tempting to delete it, but as long as there are clusters still on Flannel that might one day migrate, it stays.

## `libcalico-go/lib/ipam/vmipam`

[`libcalico-go/lib/ipam/vmipam/`](../../libcalico-go/lib/ipam/vmipam/) is the KubeVirt IP-persistence extension to the core IPAM client. It's where the alternate/active
owner-attrs dance lives (`EnsureActiveVMOwnerAttrs`, `SetOwnerAttributes`). Both the CNI plugin and Felix go through it for KubeVirt-specific allocation transitions. The
owner-attrs precondition mechanism is defined in [`ipam-core-library.md`](./ipam-core-library.md).

## Keep in sync with

- [`./ipam-core-library.md`](./ipam-core-library.md) - handle conventions, `IntendedUse`, owner-attrs precondition mechanism.
- [`./ipam-datastore.md`](./ipam-datastore.md) - affinity types (`host:<node>` vs `virtual:load-balancer`), sequence-number protection.
- [`./ipam-cni.md`](./ipam-cni.md) - the CNI side of the KubeVirt persistence handshake Felix completes.
- [`./ipam-gc.md`](./ipam-gc.md) - how tunnel handle prefixes and LB affinity types influence GC classification.
