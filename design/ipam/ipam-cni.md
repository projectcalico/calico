<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# IPAM CNI plugin

This sub-design covers the CNI plugin's use of IPAM: `cni-plugin/pkg/ipamplugin/` (the `calico-ipam` binary's implementation) and `cni-plugin/pkg/k8s/` (annotation handling). The
cross-component picture - data model, consumers, repo split - lives in the [index](./DESIGN.md). Handle-ID conventions are defined in
[`./ipam-core-library.md`](./ipam-core-library.md) and referenced here, not re-derived.

The CNI plugin ships two binaries: `calico` (main CNI) and `calico-ipam` (invoked when `conf.IPAM.Type == "calico-ipam"`). The dispatcher in
[`cni-plugin/cmd/calico/calico.go`](../../cni-plugin/cmd/calico/calico.go) routes by binary name.

## ADD flow

Invariants:

- **No partial state on failure.** Lock acquisition, the allocation call, and dual-stack family pairing each have a failure mode that must roll back, not leave half-applied state
  for the next CNI invocation to trip on.
- **Lock then clock.** The 90s allocation timeout starts *after* the host-wide IPAM lock is acquired (see [The IPAM lock](#the-ipam-lock)). Otherwise lock contention burns the
  budget before any allocation work runs.

`cmdAdd` in [`cni-plugin/pkg/ipamplugin/ipam_plugin.go`](../../cni-plugin/pkg/ipamplugin/ipam_plugin.go) is the entry point. The flow is straightforward client construction →
pool resolution → lock → `AutoAssign` → return. The design-relevant steps are:

- **KubeVirt detection.** A pod name prefixed `virt-launcher-` triggers a VMI fetch. When `IPAMConfig.KubeVirtVMAddressPersistence` is enabled, the handle ID switches from
  pod-scoped to VM-scoped (`vmipam.CreateVMHandleID`) and existing IPs on that handle are reused. This is what makes the IP follow the VM across pod recreations and live migration.
  The two handle paths must stay separate - folding them collapses VM persistence.
- **Pool resolution precedence.** Per-pod annotation > per-namespace annotation > conf default > all enabled pools. `utils.ResolvePools` accepts pool names or CIDRs. The precedence
  is user wire surface; reordering it is a deprecation cycle, not a refactor.
- **Lock-then-clock.** Acquire the host-wide IPAM lock before the 90s allocation timeout starts. See [The IPAM lock](#the-ipam-lock).
- **Boundary mask.** `AutoAssign` returns block-masked CIDRs (so callers can program per-block routes); the CNI plugin narrows to `/32` (`/128`) at its boundary. Don't push the
  narrowing back into the library.

Static / BYO IP and pool / floating-IP annotations are handled inside `cni-plugin/pkg/k8s/k8s.go` before this flow runs - see [Annotations](#annotations).

**Review notes**

- KubeVirt VM persistence relies on the handle ID being VM-scoped, not pod-scoped. Don't fold the two handle paths together.
- Pool resolution is hot path. `ResolvePools` was hand-optimized in https://github.com/projectcalico/calico/pull/9891; preserve the fast path.
- Don't log `stdinData` - it may contain `K8sAuthToken` / `K8sClientKey`. See `cni-plugin/pkg/k8s/k8s.go`.

## DEL flow

Invariants:

- **DEL is idempotent.** Any subset of block, handle, or allocation may already be gone. "Not found" is success.
- **Release by both handle forms.** The primary handle (`<network>.<container-id>`) plus the workload-ID handle (`<namespace>.<pod>`). Skipping the second leaks IPs across CRI
  container-ID changes and across v2.x-era allocations.
- **KubeVirt DEL is not "release immediately."** Clear owner attrs first; release only when the VM/VMI is gone and all attrs are empty.

`cmdDel` in the same file. The standard path releases by both handle forms (primary `<network>.<container-id>` then workload-ID `<namespace>.<pod>`); the second is what survives
CRI container-ID rotation and pre-v3 allocations. `ErrorResourceDoesNotExist` at this stage is success, not failure - any subset of block / handle / allocation may already be gone.

KubeVirt with persistence is the exception: the IP must survive pod deletion so it follows the VM through live migration. The plugin fetches the VMI, checks `DeletionTimestamp`,
enumerates via `IPsByHandle`, and clears owner attrs through `SetOwnerAttributes` under preconditions. `ReleaseByHandle` runs only when the VM/VMI itself has `DeletionTimestamp`
*and* every IP's owner attrs are empty - that's the handshake that lets Felix race the active/alternate swap without losing the IP.

**Review notes**

- Always release by both the primary handle and the workload-ID handle. Dropping the second call leaks IPs across CRI container-ID changes and across upgrades from v2.x-era
  allocations.
- DEL must be idempotent. A retry that fails because the block is gone is a bug, not a feature.
- KubeVirt DEL is not "release immediately." The `SetOwnerAttributes` preconditions exist because Felix can race the active/alternate swap; if the precondition fails, the CNI
  plugin retries.
- Don't expand "not found" tolerance into "any error tolerated." It's specifically `ErrorResourceDoesNotExist` and the not-found-by-handle case.

## Annotations

User-facing wire surface - breaking parsing or semantics here is a user-visible incident. Handled in [`cni-plugin/pkg/k8s/k8s.go`](../../cni-plugin/pkg/k8s/k8s.go). Namespace
annotations are read as defaults; per-pod annotations override.

| Annotation | What it does |
|---|---|
| `cni.projectcalico.org/ipAddrs` | JSON array of IPs. Each IP allocated via `AssignIP` - goes through IPAM, tracked normally. |
| `cni.projectcalico.org/ipAddrsNoIpam` | JSON array of IPs. **Bypasses IPAM entirely**, no allocation record. Requires `feature_control.ip_addrs_no_ipam=true`. |
| `cni.projectcalico.org/ipv4pools`, `ipv6pools` | Pool names or CIDRs scoping the allocation. Feeds `utils.ResolvePools` ahead of the conf default. |
| `cni.projectcalico.org/ipFamilies` | `["IPv4","IPv6"]` - controls which families to assign. |
| `cni.projectcalico.org/floatingIPs` | JSON array of external IPs to DNAT to the pod. Stored as `IPNAT{InternalIP, ExternalIP}` on the WEP; Felix consumes downstream. Requires `feature_control.floating_ips=true`. |

`ipAddrs` and `ipAddrsNoIpam` look similar; the code paths diverge. `ipAddrs` goes through `AssignIP`, so the IP appears in an `IPAMBlock` and the GC will see it. `ipAddrsNoIpam`
skips IPAM, the IP is whatever the user wrote, and nothing else in Calico knows the allocation exists - the user is responsible for not picking conflicts.

**Review notes**

- Annotation names and values are user wire surface. Don't rename, don't tighten parsing, don't reject inputs that previously worked. If the semantics need to change, that's a
  deprecation cycle, not a refactor.
- `ipAddrsNoIpam` and `floatingIPs` are feature-gated for a reason. Don't quietly drop the feature-gate check.
- Per-pod overrides per-namespace overrides conf default. Don't reorder the precedence.
- `floatingIPs` are consumed by Felix via the WEP `IPNAT` list - changes here that affect format need to land with the Felix side, not after.

## Platform differences

`ipam_plugin.go` is shared; the platform splits are file-level GOOS shims and a small set of args set differently on Windows.

- Lock file: Linux defaults to `/var/run/calico/ipam.lock` ([`ipam_lock_linux.go`](../../cni-plugin/pkg/ipamplugin/ipam_lock_linux.go)); Windows to `c:\CalicoWindows\ipam.lock`
  ([`ipam_lock_windows.go`](../../cni-plugin/pkg/ipamplugin/ipam_lock_windows.go)).
- Binary: Windows enters through `node/cmd/calico-ipam`.
- Windows forces `StrictAffinity=true` (HNS can't route remote affinity blocks). `WindowsUseSingleNetwork` collapses to `MaxBlocksPerHost = 1`. `HostReservedAttrIPv4s` reserves the
  first three and last IP of each block under the literal handle `windows-reserved-ipam-handle`. The reserved-handle name is parsed elsewhere - don't rename it.

## Dual-stack

If the request asks for both v4 and v6, `AutoAssign` returns one `IPAMAssignments` per family. The CNI plugin treats a half-success as a failure: if v4 came back populated and v6
came back empty (or vice versa), release the successful family immediately and surface a partial-fulfilment error to kubelet. Otherwise the pod silently runs single-stack, which is
worse than failing the ADD: the user asked for dual-stack and didn't get it.

**Review notes**

- Half-success must release the successful family. Leaving a single-family allocation in place when the request was dual-stack is an IP leak from kubelet's perspective - the pod
  won't come up, but the IP is still claimed.
- The `ipFamilies` annotation can narrow the request to one family. Don't surface "missing the other family" as an error when the user asked for only one.

## The IPAM lock

`acquireIPAMLockBestEffort` in [`cni-plugin/pkg/ipamplugin/ipam_plugin.go`](../../cni-plugin/pkg/ipamplugin/ipam_plugin.go) takes a `flock` on the path from `conf.IPAMLockFile`,
falling back to the platform default. The lock is per-host and held for the duration of the ADD (or DEL) call.

What it protects against: two `calico-ipam` invocations on the same node racing each other. CAS on `IPAMBlock` would technically serialize the persisted state, but pre-allocation
work (resolving pools, choosing a block, claiming a fresh affinity) is multi-step and the second invocation would otherwise waste a full retry budget bouncing off the first.
Holding the lock single-flights per-host allocation; the CAS protocol handles cross-host conflicts.

Lock-then-clock: the 90s allocation timeout starts **after** the lock is acquired, not before. Previously the timer started before the lock wait so a busy node could burn the
entire budget on lock contention and then fail the ADD with no allocation attempt. Fix landed in https://github.com/projectcalico/calico/pull/11824.

**Review notes**

- Lock first, then start the timeout. The clock starts after `acquireIPAMLockBestEffort` returns, not before.
- The lock is best-effort: if acquisition fails (permissions, missing dir) the function logs and returns a no-op unlock so allocation proceeds. Don't promote this to a hard failure
  - the CAS layer is still correct, the lock is a contention optimization.
- The lock is host-local. It doesn't protect against another node racing for the same block; the BlockAffinity two-phase claim does that.
- Don't take the lock around the libcalico client construction or other slow setup. Hold it only across the allocation call.

## Keep in sync with

- [`./ipam-core-library.md`](./ipam-core-library.md) - handle IDs are defined there; the CNI plugin is one consumer of that convention.
- [`./ipam-datastore.md`](./ipam-datastore.md) - block / handle state model that DEL idempotency relies on.
- [`../../cni-plugin/pkg/ipamplugin/`](../../cni-plugin/pkg/ipamplugin/) - a `DESIGN.md` stub in that directory will point back here.
