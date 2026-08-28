<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Pod netns resolution

Felix's dataplane increasingly needs to **act inside a local pod's
network namespace** — open a socket, read or set per-netns kernel
state, attach a probe, read a socket option, fix in-pod interface
config — and, for BPF cgroup hooks (e.g. the connect-time load
balancer), needs a per-pod identifier it can key on at `connect(2)`
time. Both needs reduce to the same precondition Felix historically
lacked: a stable handle to each local pod's netns.

`netnsManager` (`felix/dataplane/linux/netns_mgr.go`) is the single
per-node owner of that resolution. It watches WorkloadEndpoint
updates, resolves every local pod's netns path and its kernel-stable
**netns cookie** (`SO_NETNS_COOKIE`), caches both, and exposes them to
any consumer keyed by `*proto.WorkloadEndpointID`:

- `OpenNetnsForWEP(id) (ns.NetNS, error)` — the FD use case; the caller
  `Close()`s the handle. Returns `ErrNetnsUnresolved` when nothing is
  resolved yet (retry later), or the underlying open error otherwise.
- `CookieForWEP(id) (uint64, bool)` — the cheap-lookup use case (BPF
  maps keyed by netns cookie), without re-opening the netns.

The manager ships as infrastructure with **no consumer in its own PR**;
the first consumer (CTLB-skip) lands in a separate, dependent design.

## Three-tier resolution

Resolution walks a fallback chain, first non-empty result wins:

| Tier | Source | Package | Notes |
|---|---|---|---|
| 1 | CNI-set annotation `cni.projectcalico.org/podNetns` on the WEP | (on `proto.WorkloadEndpoint.netns_path`) | Fast path for the Calico-CNI case. The CNI plugin canonicalises `args.Netns` with `EvalSymlinks` at `cmdAdd` and writes it via the `pods/status` subresource. |
| 2 | CRI runtime lookup by pod UID | `felix/cri` | Cross-CNI fallback. Lists the ready sandbox for the pod UID, extracts the sandbox PID from the runtime `Info` JSON, derives `<procRoot>/<pid>/ns/net`. Disabled when no CRI socket is available. |
| 3 | `/proc`-cgroup UID scan | `felix/netns` | Last-resort safety net. Finds a live process whose cgroup path mentions the pod UID (dash or underscore form) and uses its `<procRoot>/<pid>/ns/net`. |

The pod UID (`proto.WorkloadEndpoint.uid`) is the stable key Tiers 2/3
use when the annotation is absent (pods admitted by another CNI in a
chain, pods pre-dating the annotation rollout, upgrade windows).

### Data flow (plumbing)

```
Calico CNI (cmdAdd) → Pod annotation cni.projectcalico.org/podNetns = EvalSymlinks(args.Netns)
libcalico-go syncer → v3 WorkloadEndpoint annotation + UID
                    → model.WorkloadEndpoint{ NetnsPath, UID }
felix calc graph    → proto.WorkloadEndpoint{ netns_path = 21, uid = 20 }
netnsManager        → three-tier resolve → { wepKey → path, wepKey → cookie }
```

**Review note.** The annotation is a **trust anchor**: Felix opens the
path and reads a cookie from it, so a user able to overwrite it could
redirect Felix into an arbitrary netns. It is protected by a
`ValidatingAdmissionPolicy`
(`api/admission/cniannotations.validatingadmissionpolicy*.yaml`) that
diffs old vs new and rejects any add/change/remove of the four
Calico-managed output annotations (`podIP`, `podIPs`, `containerID`,
`podNetns`) on `pods`/`pods/status`, CREATE/UPDATE, except from Calico
SAs (on `/status`) and `system:masters` (break-glass). A change to the
managed-key set or the exemptions must be mirrored in the operator's
embedded copy — see the sync tail.

## Execution model

The three tiers have very different costs, so they run in different
places:

- **Tier 1 is inline.** The path is already on the `proto.WorkloadEndpoint`;
  `OnUpdate` resolves it on the main dataplane goroutine and reads the
  cookie (one `openat` + `getsockopt`). This is the dominant case and is
  cheap enough to stay on the loop.
- **Tiers 2 and 3 never run on the main loop.** On a Tier-1 miss (with a
  usable UID), `OnUpdate` only records the WEP in `pendingDeep` and kicks
  a **background resolver goroutine** (`runResolver` → `resolveDeepBatch`).
  That goroutine drains all pending WEPs per cycle: Tier 2 per WEP (a
  bounded CRI round-trip each), then Tier 3 as a **single batched `/proc`
  walk** for every Tier-2 miss (`netns.ResolvePodNetnsPaths`), so the
  scan is O(processes) per cycle, not O(processes × pods). A slow ticker
  retries WEPs still pending (pause container not up, CRI briefly down).
- **Results feed back through the normal pipeline.** After caching a
  result the resolver does a non-blocking send on a wakeup channel owned
  by `int_dataplane`; the apply loop sets `dataplaneNeedsSync = true` and
  a later `CompleteDeferredWork` lets consumer managers re-read the cache.

**Review notes.**
- `paths`, `cookies`, and `pendingDeep` are written from both the main
  goroutine (Tier 1) and the resolver goroutine (Tiers 2/3); all access
  is under `netnsManager.mu`. `CookieForWEP`/`OpenNetnsForWEP` (called by
  consumers on the main goroutine) also take the lock.
- The resolver only stores a result if the WEP is **still in
  `pendingDeep`** when it goes to cache it. This closes the race where
  the WEP was removed, or resolved by a later Tier-1 update, while the
  CRI/`/proc` work was in flight — the newer state wins.
- The main apply loop only runs when `dataplaneNeedsSync` is set, so the
  wakeup select case **must** set it (unlike the parent-iface kicks that
  rely on another event having set the flag).
- Do not move Tier 2/3 back onto the main loop — start-of-day can present
  hundreds of unresolved pods at once; a gRPC round-trip or `/proc` walk
  per `OnUpdate` there would stall the whole dataplane.

## Reaching host paths (no `hostPID`)

calico-node does not necessarily share the host's PID or mount
namespaces, so the resolution tiers reach host state two different ways.

**Pid-based netns paths (Tiers 2 and 3)** live in the procfs of the host
PID namespace the pods run in. Felix reads that procfs at `procRoot`,
configured by `FelixConfiguration.ProcRootPath` (default `/proc`); when
calico-node lacks `hostPID`, the operator bind-mounts the host procfs
(e.g. `/host/proc`) and sets `ProcRootPath` to it. Both tiers build
`<procRoot>/<pid>/ns/net`, which Felix can open directly because it reads
`procRoot` directly (`felix/netns`'s `CookieByPath`, `felix/cri`'s path
built under the client's `procRoot`).

**Host-mount-namespace paths (Tier 1 and the CRI socket)** — the CNI-set
netns file (e.g. `/run/netns/cni-<uuid>`) and the CRI socket live in the
host's **mount** namespace, which calico-node does not bind-mount. Felix
reaches them through `<procRoot>/1/root` — host PID-1's root in the same
`procRoot` procfs, i.e. the host mount namespace — regardless of which PID
namespace calico-node runs in, so this does **not** depend on `hostPID=true`
(`/host/proc/1/root` in production, `/proc/1/root` when `procRoot` is
`/proc`). Absolute symlink targets along that path (e.g. `/var/run` →
`/run`) are resolved against the host view with `filepath-securejoin`'s
`SecureJoin` rooted there (`felix/cri`'s `viaHostRoot`, `felix/netns`'s
`hostPath`), not the container's `/` — a naive prefix would re-root the
target at the container root and miss the real inode.
`felix/cri/socket_detect.go` stat-probes a small fixed list of
well-known CRI socket paths through the same mechanism; the probe is
overridden by `FelixConfiguration.CRISocketPath`.

**Review note.** There is one knob: `FelixConfiguration.ProcRootPath`
(`procRoot`). The pid-based tiers open their `<procRoot>/<pid>/ns/net`
path directly; the host-mount-namespace tiers re-root through
`hostMountRoot(procRoot)` = `<procRoot>/1/root` (`felix/cri` and
`felix/netns` each derive it — keep the SecureJoin-with-naive-fallback
shape in both). Tests drive both by passing a `t.TempDir()` as `procRoot`.

## Where it sits, and why it's standalone

`netnsManager` is registered once per BPF-mode bring-up in
`int_dataplane.go`, **immediately after `bpfEndpointManager`** and before
any feature-specific consumer. Registration order is dispatch order, so a
consumer's `OnUpdate`/`CompleteDeferredWork` sees a resolved Tier-1 cookie
for the same WEP in the same cycle; Tier-2/3 results arrive later via the
wakeup.

It is deliberately **not** folded into `endpointManager` or
`bpfEndpointManager`: it is a query service (`OpenNetnsForWEP`/
`CookieForWEP`), not endpoint-attach state; its per-WEP work is gated only
by WEP existence (sandbox up), not interface presence (the `cali*` veth)
as the BPF endpoint manager's is. It tracks **local** WEPs only — the calc
graph delivers only local WEPs to Linux-dataplane managers.

It is only constructed in BPF mode today because the only consumer is
BPF-only; the package boundary is fine for either dataplane, so the
registration moves out of the BPF branch if a non-BPF consumer arrives.

## Testing

- `felix/netns`, `felix/cri`: fake `/proc` trees and host-root prefix over
  `t.TempDir()`, fake CRI sockets; cover happy path, ENOENT, broken
  symlinks, pid-from-info variants, socket layouts, and the batched scan
  (one walk resolving several UIDs).
- `felix/dataplane/linux/netns_mgr_test.go`: drives `resolveDeepBatch`
  directly to exercise each tier deterministically; covers
  `ErrNetnsUnresolved`, cookie-change-on-path-change, drop-on-remove,
  drop-and-retry-on-failed-open, the batched single scan, and the wakeup.
- Per-platform behaviour (CRI `Info` shape, socket path, whether the
  `/host/proc` mount is permitted) is caught by an automated regression
  E2E across the supported platform matrix — the risk here is
  overwhelmingly per-platform and unit tests can't reach it.

## Keep this in sync

- The VAP is the source of truth in
  `api/admission/cniannotations.validatingadmissionpolicy*.yaml`; the
  operator ships a copy in
  `pkg/imports/admission/{calico,enterprise}/cniannotations.yaml`,
  reconciled via its managed-admission-policy machinery and gated by the
  `Installation.spec.cniAnnotationsPolicy` toggle. A change to the managed
  keys or exemptions must update **both** repos.
- The `/host/proc` bind-mount is added by the operator
  (`pkg/render/node.go`), which must also set `FelixConfiguration.ProcRootPath`
  (or `FELIX_ProcRootPath`) to that mount so Felix reads the host procfs
  there; the default `/proc` only suits calico-node sharing the host PID
  namespace. Removing the operator's remaining `hostPID=true` usage
  (process-path collection) is a coordinated follow-up because the consumer
  is Enterprise-only.
- The proto contract (`felix/proto/felixbackend.proto`,
  `WorkloadEndpoint.uid = 20`, `netns_path = 21`) and its plumbing through
  `libcalico-go` are part of this design; a change to what's carried
  updates [`calc-graph.md`](./calc-graph.md) / [`dataplane.md`](./dataplane.md)
  as well.
