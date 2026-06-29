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

# eBPF dataplane — XDP programs and the XDP→TC handoff

XDP's narrow role in Calico (untracked-policy fast-drop / early-accept), how packets that XDP accepted hand off to TC via `xdp2tc` metadata, and the `BPFForceTrackPacketsFromIfaces` per-interface opt-out for 3rd-party DNAT interoperability.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## XDP programs and the XDP→TC handoff

### What XDP is used for in Calico

XDP programs run in the NIC driver's receive path, before the kernel
allocates an `skb`. In Calico they are attached to HEPs that support
XDP (hardware or generic-XDP fallback) alongside the TC programs.
Their purpose is narrow but important:

- **Untracked policy.** Drop-list matching at line rate. Traffic that
  a HEP's untracked policy drops never enters the kernel's `skb`
  path at all — the NIC DMA buffer is recycled. This is the fast
  defence against volumetric attacks and obvious-hostile traffic.
- **Early accept.** If untracked policy explicitly allows a packet,
  XDP marks it as "already vetted" so the TC program downstream
  does not re-run policy.

XDP is stateless: no conntrack, no NAT. It only carries rules that
the admin has marked as not needing connection tracking. Anything
subtler — service NAT, policy that depends on flow state,
fragments — falls through to TC.

### The XDP→TC handoff

A packet that XDP has accepted still needs to go through the rest
of the dataplane — most obviously it still needs conntrack, NAT and
forwarding decisions. The handoff is via packet metadata:

- XDP calls `xdp2tc_set_metadata(ctx, CALI_META_ACCEPTED_BY_XDP)`
  (`felix/bpf-gpl/metadata.h`, used from `xdp.c`). The metadata is
  written into a region of the packet buffer that XDP reserves and
  TC can read.
- On the TC ingress hook, the program calls
  `xdp2tc_get_metadata(skb)` and, on
  `CALI_META_ACCEPTED_BY_XDP`, sets
  `skb->mark = CALI_SKB_MARK_BYPASS_XDP` (`bpf.h`) and skips the
  policy step.

The same jump-map / preamble machinery from [bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md) applies. XDP has its
own preamble (`xdp_preamble.c`) and its own jump map
(`xdp_cali_progs`).

### Force-track interfaces

XDP untracked policy means a packet can bypass the regular
tracked-flow path. For some interfaces (e.g. ones that carry
`*tables`-managed DNAT, see [bpf-conntrack-flowstate.md → 3rd-party DNAT on host traffic](./bpf-conntrack-flowstate.md)) this is wrong — the packet must
be tracked so that netfilter's conntrack can match on return.
Calico supports per-interface opt-out via
`BPFForceTrackPacketsFromIfaces`. The generated `*tables` rule
(`ChainRawUntrackedFlows` via `BPFForceTrackPacketsFromIfaces` in
`felix/rules/static.go`) forces traffic on those interfaces through
the regular tracked path regardless of what XDP would have done.

### Review notes

- A change that adds a new XDP-emitted signal needs a metadata
  flag (`CALI_META_*`), corresponding code in
  `xdp2tc_set_metadata` / `xdp2tc_get_metadata`, and a TC-side
  handler. Do not overload `skb->mark` directly from XDP — the
  metadata path is the only place where XDP→TC signal travel is
  preserved across the skb allocation boundary.
- A change that makes TC skip additional work on
  `CALI_SKB_MARK_BYPASS_XDP` must keep conntrack and NAT working
  — those happen _after_ the XDP-accept check in the TC main
  program and are not skipped.
- An interface type that requires packets to traverse `*tables`
  conntrack (existing or new 3rd-party DNAT) needs to end up in
  `BPFForceTrackPacketsFromIfaces`; without it, XDP's fast-drop
  can make the packet invisible to netfilter.




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
