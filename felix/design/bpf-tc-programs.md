<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# eBPF dataplane — TC program layout

How the per-interface BPF programs are organised: the attach mechanisms (clsact, TCX, netkit) and the netkit-specific concessions that follow, the per-interface preamble, the two-tier jump maps that decouple per-endpoint policy from generic packet-handling, the `skb->cb` allow/deny convention, and the fast/debug path machinery. Also covers the `cali_iface` ifstate map and the attach-gap protection it enables.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## TC program layout

Attaching a TC program directly per interface does not scale: Felix
would have to reload the full program set every time policy changes
and every time it restarts. The current design decouples the programs
that rarely change (the packet-handling code) from the programs that
frequently change (per-endpoint policy).

### Attach mechanisms (clsact, TCX, netkit)

The same packet-processing programs are attached via one of three
kernel mechanisms, selected per interface:

- **Legacy clsact (TC)** — the classic `BPF_PROG_TYPE_SCHED_CLS`
  on the per-interface clsact ingress/egress filter. The fallback
  on kernels that do not support TCX.
- **TCX** — preferred when the kernel supports it. Same program
  type as clsact, attached via `bpf_link` to the per-interface
  TCX hook.
- **Netkit, workload interfaces only** — when the workload
  interface is a netkit device (rather than a veth), Felix
  attaches via the netkit attach API, with `BPF_NETKIT_PRIMARY`
  for the host-side (to-pod, TC-egress equivalent) program and
  `BPF_NETKIT_PEER` for the peer (from-pod, TC-ingress
  equivalent) program. Felix detects netkit support at runtime
  (`tc.IsNetkitSupported` in `felix/bpf/tc/attach.go`) and only
  uses netkit attachment for the workload interfaces it
  manages — host or data-plane netkit devices are not Felix's
  concern. The internal signal `AttachPoint.Netkit` is set
  separately from the user-facing `BPFAttachType` enum so that
  the override is scoped to Felix's own detection.

A netkit-enabled cluster is not a wholesale swap. Felix selects
the attach mechanism per attach point at attach time
(`calculateTCAttachPoint` in `bpf_ep_mgr.go`): TC clsact or TCX
for HEPs, tunnels, the bpfnat and loopback pair, and any workload
interface that is still a regular veth; netkit only for workload
interfaces that are themselves netkit devices. A single Felix
process therefore programs both styles concurrently — the
supporting machinery (jump-map sets, globals plumbing, cleanup
paths) handles both in parallel rather than switching wholesale
when netkit is enabled.

The packet-handling code is mechanism-agnostic — same preamble,
same jump-map layout, same policy program — with four
netkit-specific concessions:

- **Separate jump maps.** Netkit programs have a different
  `expected_attach_type` from TC/TCX; the kernel rejects a
  prog_array that mixes the two. Felix maintains a parallel set
  of `prog_array` maps for netkit, pinned under
  `bpfdefs.NetkitPinDir` (`/sys/fs/bpf/netkit`) instead of the
  TCX directory. See `NetkitJumpMaps` in
  `felix/bpf/bpfmap/bpf_maps.go` and `netkitPinOverrides` in
  `felix/bpf/hook/map.go`. The endpoint manager carries a
  matching `netkitJumpMapAllocs` allocator alongside the TC one
  in `felix/dataplane/linux/bpf_ep_mgr.go`.
- **`host_ifindex` global.** A netkit peer program runs in the
  pod's network namespace, so `skb->ifindex` on a peer-program
  call is the *peer* ifindex, not the host-side one. Felix
  populates `host_ifindex` in the per-attach-point globals
  (`felix/bpf-gpl/globals.h`). Helpers keyed by host-side
  ifindex — `wep_rpf_check` in `rpf.h`, the QoS map lookup in
  `qos.h`, the per-interface counters macro in `types.h`, and
  the FIB redirect path in `fib_co_re.h` — read `host_ifindex`
  first and fall back to `skb->ifindex` only when it is zero
  (the TC/TCX case).
- **No `bpf_redirect_peer`.** The helper requires
  `skb_at_tc_ingress` context; netkit programs run in xmit
  context where the helper silently drops the packet. Felix
  forces `RedirectPeer = false` on netkit attach points so the
  FIB path uses plain `bpf_redirect`. Set in
  `calculateTCAttachPoint` in `bpf_ep_mgr.go`.
- **Synchronous detach on cleanup.** `detachAndRemoveLinkPins`
  in `felix/bpf/tc/cleanup.go` opens each pinned link, calls
  `Detach()`, and only then unlinks the pin file. The same
  shape applies to TCX cleanup; relying on the kernel's
  auto-detach when the last reference closes is not enough.

### The preamble

The program that is actually attached to the TC hook on each
interface is a **preamble**
(`felix/bpf-gpl/tc_preamble.c` → `cali_tc_preamble`). It is tiny, fast
to load, and its only job is to:

1. Pick the IPv4 or IPv6 globals struct based on `skb->protocol` and
   copy it into per-CPU state. The rest of the program chain reads
   globals from that state, so a single copy amortises the cost.
2. If a log filter is configured for this interface, tail-call it.
3. Otherwise tail-call the "main" packet-processing program directly.

XDP has an equivalent preamble in `xdp_preamble.c`. The cgroup
connect-time hooks ([bpf-services.md → Connect-Time Load Balancer (CTLB)](./bpf-services.md)) are attached directly — they have no preamble.

Because the preamble is cheap to reload, Felix can swap it per
interface without re-verifying the large program chain it fronts.

### Two-tier jump maps

Packet-processing programs are organised into two jump maps per
direction:

- **Generic programs map** — `cali_progs_ing` (TC ingress),
  `cali_progs_egr` (TC egress), `xdp_cali_progs` (XDP). Holds the
  code that is the same across all endpoints of the same kind: the
  main program, allowed/drop entry points, ICMP helpers, IP-frag
  helper, Maglev helper, TCP reset helper, etc. See
  `felix/bpf/hook/map.go` (`tcSubProgNames`, `xdpSubProgNames`).
- **Per-endpoint programs map** — `cali_jump_ing`, `cali_jump_egr`,
  `xdp_cali_jump`. Holds the policy program generated for each
  interface+direction, and the pcap log filter if one is installed
  (see [bpf-observability.md → Debug log filters](./bpf-observability.md)). The policy program is regenerated and re-loaded
  whenever the rules for that endpoint change; the generic code above
  is untouched.

The split is what lets policy updates be cheap: Felix only has to
rewrite a couple of entries in the per-endpoint map, not replace any
attached programs. The kernel's tail-call mechanism makes the switch
atomic per-program-index.

Splitting the two TC directions (ingress vs egress) into separate maps
is a kernel-6.12 requirement (TCX programs on each direction have a
distinct program type and a jump map is typed for a single program
type). See the comment at the top of
`felix/bpf-gpl/jump.h`.

Both maps are sized generously. The per-endpoint map is large (240k
slots) because each endpoint gets two policy programs (one per TC
direction). Policy programs themselves are _not_ duplicated for the
fast and debug paths — one compiled policy program serves both, and
the caller's continuation (encoded in `skb->cb[0]`/`cb[1]`, below)
is what decides which path the packet continues on. A handful of the
generic sub-programs in the other map (main, allowed, drop, ICMP,
etc.) do have separate fast and debug variants occupying distinct
slots; see `allocateLayout` in `felix/bpf/hook/map.go` for the
placement — it uses an offset for debug variants but leaves
`SubProgTCPolicy` at a single index.

### Caching of generic programs

`hook.ProgramsMap` (in `felix/bpf/hook/map.go`) caches one loaded
object file per `AttachType`. An `AttachType` is the tuple of flags
that changes which sub-programs are compiled in: hook (TC
ingress/egress or XDP), whether the interface is a WEP, HEP, tunnel,
DSR-enabled, cgroup, etc. `LoadObj` loads the object at most once per
`AttachType` and returns a `Layout` that maps every sub-program to the
jump-map index it was placed at.

`GetApplicableSubProgs` filters the list based on capability: the
host-CT-conflict helper is only loaded for HEP egress, the Maglev
helper only where Maglev can be used, the IP-frag helper only on
attach points that run defrag. If the kernel rejects the IP-frag
program (older verifiers can fail on it), the load is retried with
that sub-program disabled — which is the only sub-program that may
legitimately be missing at runtime.

### skb->cb[0] and skb->cb[1]: continuation addresses

The per-endpoint policy program is called from generic
(per-endpoint-independent) programs. The convention is that before
tail-calling into policy, the caller writes:

- `skb->cb[0]` = the jump-map index to tail-call on **allow**,
- `skb->cb[1]` = the jump-map index to tail-call on **deny**.

Policy reads those and tail-calls into the appropriate successor.
Two things fall out of this convention:

- **Policy is callable from any generic program.** The generic
  callers — main, Maglev, new-flow — each know which jump-map
  indices they want to continue at, write them into `cb[]`, then
  tail-call the single per-endpoint policy program. No per-caller
  specialisation of policy is needed.
- **The debug path reuses the same policy program as the fast path.**
  The fast-path caller writes fast-path continuation indices; the
  debug-path caller writes debug-path continuation indices. Policy
  itself doesn't need a debug variant — the continuation passed in
  `cb[]` is what carries the path selection.

The convention is encoded in `__CALI_JUMP_TO_POLICY` in `jump.h`: it
defaults to `cb[0] = PROG_INDEX_ALLOWED`, `cb[1] = PROG_INDEX_DROP`,
but callers that want a different continuation (for example the
Maglev program, which wants to re-enter the main program on allow)
write their own values before jumping.

### Fast path and debug path

Emitting a log line per packet is far too expensive for production,
so the dataplane is built twice: once without log statements ("fast
path") and once with them enabled ("debug path"). Each sub-program
therefore has two entries in `enum cali_jump_index` in `jump.h`, for
example `PROG_INDEX_MAIN` and `PROG_INDEX_MAIN_DEBUG`. The
`PROG_PATH(idx)` macro selects at compile time based on
`CALI_LOG_LEVEL`.

Both the fast-path and debug-path objects are loaded into the same
jump map, at different indices. `allocateLayout` in
`felix/bpf/hook/map.go` uses an offset of `SubProgTCMainDebug` when
placing debug programs, so fast-path and debug-path sub-programs never
collide.

Path selection depends on `BPFLogLevel`:

- `BPFLogLevel` is _not_ `debug`: only the fast path is loaded. The
  preamble jumps directly to the fast-path main.
- `BPFLogLevel == debug` and no user-specified filter: both paths
  are loaded and a **match-all** log filter is installed. Every
  packet takes the debug path. Using a match-all filter (rather
  than special-casing "no filter") keeps the preamble logic
  uniform.
- `BPFLogLevel == debug` with a user-specified filter: both paths
  are loaded; the filter decides per-packet whether each packet
  takes the fast or debug path. Log filtering is covered in [bpf-observability.md → Debug log filters](./bpf-observability.md).

### Attach-gap prevention

An interface exists briefly before Felix attaches a BPF program to it.
If another interface's BPF program forwarded a packet to the unready
one via `bpf_redirect`, the packet would bypass the `*tables` drop
rules that Felix maintains for this window. To prevent this, Felix
maintains the `cali_iface` hash map (key: ifindex,
`felix/bpf/ifstate/map.go` and `felix/bpf-gpl/ifstate.h`). The value
carries per-interface flags — notably `IFACE_STATE_V4_READY` /
`IFACE_STATE_V6_READY` and `IFACE_STATE_WEP` / `IFACE_STATE_HEP` —
plus the per-direction policy jump-map indices.

`fib_approve` (in `felix/bpf-gpl/fib_common.h`) consults this map
before approving a direct forward. For any connection that is not yet
confirmed in conntrack, a forward to a WEP whose interface is not
ready is refused; the packet is marked `CALI_SKB_MARK_SKIP_FIB` and
handed to the host stack, where the existing `*tables` attach-gap
drop rules apply. Confirmed (already-established) flows are allowed
through directly — the policy check happened when the flow was
created.

### Review notes for this section

- A new sub-program added to the generic program chain needs:
  - an entry in `enum cali_jump_index` in `felix/bpf-gpl/jump.h` with
    a matching `_DEBUG` variant,
  - a corresponding `SubProg*` constant and name in
    `felix/bpf/hook/map.go` (`tcSubProgNames` / `xdpSubProgNames`),
  - filtering in `GetApplicableSubProgs` if the program is not needed
    for every `AttachType`.
- A new per-endpoint program (something Felix reprograms per
  interface) belongs in the per-endpoint jump map (`cali_jump_*`),
  not the generic one. Generic programs are shared; per-endpoint
  programs are not.
- Any caller that tail-calls into the policy program must set
  `skb->cb[0]` and `skb->cb[1]` to valid jump-map indices first.
  Calling the policy program without setting them produces
  hard-to-debug drops on the allow or deny path.
- A change that adds a new field to the `cali_iface` value — or a new
  flag — needs a map-version bump (see `MapParams.Version` in
  `felix/bpf/ifstate/map.go`) because the kernel refuses to pin two
  different layouts under the same name.
- A change that makes BPF forward a packet directly that used to go
  through `*tables` should consult `fib_approve` (or an equivalent
  check) for the ifstate-ready flag; otherwise it reopens the
  attach-gap hole.
- Helpers and maps keyed by the host-side ifindex must read
  `host_ifindex` from globals first and fall back to
  `skb->ifindex` only when it is zero. Reading `skb->ifindex`
  directly works for TC/TCX but on a netkit peer program keys
  the lookup on the peer ifindex, which the host-side maps
  don't know about.
- Code paths that depend on TC ingress context (helpers that
  check `skb_at_tc_ingress`, etc.) must be gated off for netkit
  attach points. `bpf_redirect_peer` is the existing example,
  gated via `RedirectPeer = false` on netkit. A path that takes
  a similar context dependency without an equivalent gate will
  silently misbehave on netkit.
- Every generic sub-program in the chain must be reachable
  through both the TC/TCX jump maps and `NetkitJumpMaps`. The
  shared `hook.ProgramsMap` machinery handles this when the
  sub-program is registered via `tcSubProgNames` and the
  per-direction `MapPinOverrides` are honoured in the
  AttachPoint — bypassing that machinery (e.g. pinning into a
  specific path) silently breaks netkit.




---

## Keep this doc in sync with the code

A change to how the BPF dataplane works in the area this file
covers must update the relevant section in the same PR — new
mechanism, new flag, new map field, new config knob, or any
change to the packet path. Exemptions: (a) bug fix restoring
documented behaviour, (b) mechanical refactor with no observable
change, (c) comment / log-message edits, (d) dependency bumps.
If in doubt, update.

Cross-cutting rules that apply to **every** BPF change (map
versioning, mark discipline, sub-program registration, kernel-
version sensitivity) live in
[`bpf-overview.md` → Cross-cutting review notes](./bpf-overview.md).
