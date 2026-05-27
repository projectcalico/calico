<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM CNI plugin

This sub-design covers the CNI plugin's use of IPAM:
`cni-plugin/pkg/ipamplugin/` (the `calico-ipam` binary's
implementation) and `cni-plugin/pkg/k8s/` (annotation handling). The
cross-component picture - data model, consumers, repo split - lives
in the [index](./DESIGN.md). Handle-ID conventions are defined in
[`./ipam-core-library.md`](./ipam-core-library.md) and referenced
here, not re-derived.

The CNI plugin ships two binaries: `calico` (main CNI) and
`calico-ipam` (invoked when `conf.IPAM.Type == "calico-ipam"`). The
dispatcher in
[`cni-plugin/cmd/calico/calico.go`](../../../cni-plugin/cmd/calico/calico.go)
routes by binary name.

## ADD flow

`cmdAdd` in
[`cni-plugin/pkg/ipamplugin/ipam_plugin.go`](../../../cni-plugin/pkg/ipamplugin/ipam_plugin.go)
is the entry point. The walk:

1. Load `NetConf` from stdin, build a libcalico client via
   `utils.CreateClient`. Honours `KUBECONFIG`,
   `ETCD_ENDPOINTS`, `K8S_API_TOKEN`, `DATASTORE_TYPE` and
   TLS-cert envs.
2. Extract pod identifiers from CNI args.
3. KubeVirt detection: if the pod name starts with
   `virt-launcher-`, fetch the VMI. If
   `IPAMConfig.KubeVirtVMAddressPersistence` is enabled, switch
   to a VM-based handle ID via `vmipam.CreateVMHandleID` and try
   to reuse existing IPs on that handle so the IP follows the VM
   across pod recreations and live migration.
4. Compute the handle ID (see
   [`./ipam-core-library.md`](./ipam-core-library.md) for the
   convention). Default form is
   `<network-name>.<container-id>` via
   `cni-plugin/internal/pkg/utils.GetHandleID`.
5. Populate `Attrs`: `AttributeNode`, `AttributeTimestamp`,
   `AttributePod` / `AttributeNamespace` for K8s pods,
   `AttributeVMIName` / `AttributeVMIUID` / `AttributeVMUID` /
   `AttributeVMIMUID` for KubeVirt.
6. Resolve pools via `utils.ResolvePools`. Order: per-pod
   annotation > per-namespace annotation > conf default > all
   enabled pools. Names or CIDRs both accepted.
7. Build `AutoAssignArgs`. `MaxBlocksPerHost = 1` when
   `WindowsUseSingleNetwork` is set, `HostReservedAttrIPv4s` on
   Windows reserves first 3 + last 1 IPs under the literal
   handle `windows-reserved-ipam-handle`, and `Namespace` is the
   K8s Namespace object so pool `namespaceSelector` matches.
   - For KubeVirt with persistence, also set
     `MaxAllocToHandlePerIPVersion = 1` so the VM-scoped handle
     can't accumulate more than one IP per family.
8. Acquire the host-wide IPAM lock - see
   [the IPAM lock section](#the-ipam-lock).
9. Call `calicoClient.IPAM().AutoAssign(ctx, args)`. Returns
   `*IPAMAssignments` per family.
10. Handle partial fulfilment - see
    [Dual-stack](#dual-stack).
11. Mask down to /32 (or /128) and return the CNI result.
    `AutoAssign` itself returns block-masked CIDRs; the CNI
    plugin narrows them at the boundary.

Static / BYO IP and pool / floating-IP annotations are handled
inside `cni-plugin/pkg/k8s/k8s.go` before this flow - see
[Annotations](#annotations).

**Review notes**

- KubeVirt VM persistence relies on the handle ID being VM-scoped, not pod-scoped. Don't fold the two handle paths together.
- `MaxBlocksPerHost = 1` for `WindowsUseSingleNetwork` is load-bearing - Windows can't route remote affinity blocks.
- Pool resolution is hot path. `ResolvePools` was hand-optimized in https://github.com/projectcalico/calico/pull/9891; preserve the fast path.
- Don't log `stdinData` - it may contain `K8sAuthToken` / `K8sClientKey`. See `cni-plugin/pkg/k8s/k8s.go`.

## DEL flow

`cmdDel` in the same file. Two paths.

Standard (non-KubeVirt):

1. `ReleaseByHandle(ctx, "<network-name>.<container-id>")` -
   the primary handle.
2. `ReleaseByHandle(ctx, "<namespace>.<pod-name>")` - the
   workload-ID handle. Backward-compat for v2.x-era allocations,
   and load-bearing for CRI container-ID changes where the
   container ID rotates while the pod lives on.
3. "Does not exist" errors at this stage are warnings, not
   failures. CNI DEL must be idempotent: any subset of block /
   handle / allocation may already be gone.

KubeVirt with persistence: the IP must survive pod deletion so
it follows the VM through live migration. Fetch the VMI, check
`DeletionTimestamp`, `IPsByHandle` to enumerate, then clear
owner attrs via
`SetOwnerAttributes` with preconditions. Only call
`ReleaseByHandle` once the VM/VMI has `DeletionTimestamp` **and**
every IP's owner attrs are empty.

**Review notes**

- Always release by both the primary handle and the workload-ID handle. Dropping the second call leaks IPs across CRI container-ID changes and across upgrades from v2.x-era allocations.
- DEL must be idempotent. A retry that fails because the block is gone is a bug, not a feature.
- KubeVirt DEL is not "release immediately." The `SetOwnerAttributes` preconditions exist because Felix can race the active/alternate swap; if the precondition fails, the CNI plugin retries.
- Don't expand "not found" tolerance into "any error tolerated." It's specifically `ErrorResourceDoesNotExist` and the not-found-by-handle case.

## Annotations

User-facing wire surface - breaking parsing or semantics here is
a user-visible incident. Handled in
[`cni-plugin/pkg/k8s/k8s.go`](../../../cni-plugin/pkg/k8s/k8s.go).
Namespace annotations are read as defaults; per-pod annotations
override.

| Annotation | What it does |
|---|---|
| `cni.projectcalico.org/ipAddrs` | JSON array of IPs. Each IP allocated via `AssignIP` - goes through IPAM, tracked normally. |
| `cni.projectcalico.org/ipAddrsNoIpam` | JSON array of IPs. **Bypasses IPAM entirely**, no allocation record. Requires `feature_control.ip_addrs_no_ipam=true`. |
| `cni.projectcalico.org/ipv4pools`, `ipv6pools` | Pool names or CIDRs scoping the allocation. Feeds `utils.ResolvePools` ahead of the conf default. |
| `cni.projectcalico.org/ipFamilies` | `["IPv4","IPv6"]` - controls which families to assign. |
| `cni.projectcalico.org/floatingIPs` | JSON array of external IPs to DNAT to the pod. Stored as `IPNAT{InternalIP, ExternalIP}` on the WEP; Felix consumes downstream. Requires `feature_control.floating_ips=true`. |

`ipAddrs` and `ipAddrsNoIpam` look similar; the code paths
diverge. `ipAddrs` goes through `AssignIP`, so the IP appears
in an `IPAMBlock` and the GC will see it. `ipAddrsNoIpam` skips
IPAM, the IP is whatever the user wrote, and nothing else in
Calico knows the allocation exists - the user is responsible for
not picking conflicts.

**Review notes**

- Annotation names and values are user wire surface. Don't rename, don't tighten parsing, don't reject inputs that previously worked. If the semantics need to change, that's a deprecation cycle, not a refactor.
- `ipAddrsNoIpam` and `floatingIPs` are feature-gated for a reason. Don't quietly drop the feature-gate check.
- Per-pod overrides per-namespace overrides conf default. Don't reorder the precedence.
- `floatingIPs` are consumed by Felix via the WEP `IPNAT` list - changes here that affect format need to land with the Felix side, not after.

## Windows quirks

The Linux helper at
[`cni-plugin/pkg/ipamplugin/ipam_lock_linux.go`](../../../cni-plugin/pkg/ipamplugin/ipam_lock_linux.go)
defaults the lock to `/var/run/calico/ipam.lock`; the Windows
helper at
[`cni-plugin/pkg/ipamplugin/ipam_lock_windows.go`](../../../cni-plugin/pkg/ipamplugin/ipam_lock_windows.go)
defaults to `c:\CalicoWindows\ipam.lock`. The binary entry point
on Windows is `node/cmd/calico-ipam`.

Behavioural differences:

- `StrictAffinity` is forced true on Windows regardless of the stored `IPAMConfig` value - Windows can't route /26 affinity blocks remotely.
- `WindowsUseSingleNetwork` collapses to `MaxBlocksPerHost = 1`.
- `HostReservedAttrIPv4s` reserves the first 3 + last 1 IPs of each block under handle `windows-reserved-ipam-handle`.
- Dual-stack on a single network is restricted (single-network mode is IPv4 only); see HNS limitations referenced in the core library.

**Review notes**

- Don't relax `StrictAffinity=true` on Windows without a routing story - the local affinity blocks are the only ones Windows can program.
- The reserved-handle name is literal and parsed elsewhere; don't rename it.
- New IPAM behavior added in `ipam_plugin.go` needs to be tested on Windows or explicitly scoped to Linux. The two code paths share most of the file.

## Dual-stack

If the request asks for both v4 and v6, `AutoAssign` returns one
`IPAMAssignments` per family. The CNI plugin treats a
half-success as a failure: if v4 came back populated and v6 came
back empty (or vice versa), release the successful family
immediately and surface a partial-fulfilment error to kubelet.
Otherwise the pod silently runs single-stack, which is worse
than failing the ADD: the user asked for dual-stack and didn't
get it.

**Review notes**

- Half-success must release the successful family. Leaving a single-family allocation in place when the request was dual-stack is an IP leak from kubelet's perspective - the pod won't come up, but the IP is still claimed.
- The `ipFamilies` annotation can narrow the request to one family. Don't surface "missing the other family" as an error when the user asked for only one.

## The IPAM lock

`acquireIPAMLockBestEffort` in
[`cni-plugin/pkg/ipamplugin/ipam_plugin.go`](../../../cni-plugin/pkg/ipamplugin/ipam_plugin.go)
takes a `flock` on the path from `conf.IPAMLockFile`, falling
back to the platform default. The lock is per-host and held for
the duration of the ADD (or DEL) call.

What it protects against: two `calico-ipam` invocations on the
same node racing each other. CAS on `IPAMBlock` would technically
serialize the persisted state, but pre-allocation work (resolving
pools, choosing a block, claiming a fresh affinity) is multi-step
and the second invocation would otherwise waste a full retry
budget bouncing off the first. Holding the lock single-flights
per-host allocation; the CAS protocol handles cross-host
conflicts.

Lock-then-clock: the 90s allocation timeout starts **after** the
lock is acquired, not before. Previously the timer started before
the lock wait so a busy node could burn the entire budget on lock
contention and then fail the ADD with no allocation attempt. Fix
landed in https://github.com/projectcalico/calico/pull/11824.

**Review notes**

- Lock first, then start the timeout. The clock starts after `acquireIPAMLockBestEffort` returns, not before.
- The lock is best-effort: if acquisition fails (permissions, missing dir) the function logs and returns a no-op unlock so allocation proceeds. Don't promote this to a hard failure - the CAS layer is still correct, the lock is a contention optimization.
- The lock is host-local. It doesn't protect against another node racing for the same block; the BlockAffinity two-phase claim does that.
- Don't take the lock around the libcalico client construction or other slow setup. Hold it only across the allocation call.

## Keep in sync with

- [`./ipam-core-library.md`](./ipam-core-library.md) - handle IDs are defined there; the CNI plugin is one consumer of that convention.
- [`./ipam-datastore.md`](./ipam-datastore.md) - block / handle state model that DEL idempotency relies on.
- [`../../../cni-plugin/pkg/ipamplugin/`](../../../cni-plugin/pkg/ipamplugin/) - a `DESIGN.md` stub in that directory will point back here.
