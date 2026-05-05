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

# eBPF dataplane — Observability surface

How the dataplane reports and tags traffic for external consumers: pcap-expression debug log filters with their fast/debug dual-path mechanism, per-flow events emitted into a ring buffer (flow logs, distinct from per-packet debug logs), QoS controls in BPF (packet-rate enforcement, DSCP marking) and the Istio ambient-mode integration that uses DSCP at TCP SYN time to signal in-mesh traffic to ztunnel.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## Debug log filters

### The problem

With `BPFLogLevel = debug`, BPF programs emit a log line at every
interesting point in the packet path. That is indispensable when
diagnosing a rare issue and catastrophic when run blindly on a loaded
cluster — the log stream overwhelms the ring buffer, packets hit
slower code, and the signal is drowned by noise.

BPFLogFilters let an operator target debug logging to a small,
specific subset of packets ("only TCP to port 80 on these two
pods") so the cost is paid only for traffic that matters.

### Fast path and debug path

The dataplane is compiled twice:

- The **fast path** has all logging calls optimised out
  (`CALI_LOG_LEVEL < DEBUG`). This is what runs on every packet in
  production.
- The **debug path** is the same code with logging enabled
  (`CALI_LOG_LEVEL == DEBUG`). Each sub-program (main, policy,
  allowed, drop, etc.) has a `_DEBUG` variant in
  `enum cali_jump_index` ([bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md)).

When no filter is configured, only the fast path is loaded. When a
filter is configured, both paths are loaded: same map, different
indices, thanks to the `SubProgTCMainDebug` offset in
`allocateLayout` (`felix/bpf/hook/map.go`).

### pcap → eBPF

The filter itself is a BPF program compiled from a pcap expression.
Doing the compilation at runtime is much cheaper than hand-assembling
a filter per rule, and reuses the familiar pcap language.
Implementation in `felix/bpf/filter/filter.go`:

1. `pcap.CompileBPFFilter` (gopacket/pcap) turns the expression into
   classic-BPF (cBPF) instructions.
2. `cBPF2eBPF` converts those to eBPF bytecode in our
   `felix/bpf/asm/asm.go` representation.
3. The filter's prologue copies packet bytes into a per-CPU scratch
   buffer (the state map) so the cBPF offsets resolve correctly; the
   epilogue either tail-calls the debug-path main (on match) or
   falls through to the fast-path main (on miss).

The filter uses the same `skb->cb[0]` / `skb->cb[1]` convention as
every other tail-caller ([bpf-tc-programs.md → TC program layout](./bpf-tc-programs.md)):

- `skb->cb[0]` = fast-path main index (no match → go here),
- `skb->cb[1]` = debug-path main index (match → go here).

### Integration with the preamble

`tc_preamble.c` checks `globals->data.log_filter_jmp`. If it is not
`-1`, the preamble sets up `skb->cb[0]` and `skb->cb[1]` and
tail-calls into the filter; otherwise it jumps directly to the
fast-path main. The per-endpoint jump map (`cali_jump_prog_map`)
holds the filter, not the generic program map — filters are
per-interface.

### BPFLogFilters and bpfCTLBLogFilter

- `BPFLogFilters` is a comma-separated list of `key=value` entries.
  The key is an interface name, `all`, `hep` or `wep`; the value is
  the pcap expression. This lets an operator attach different
  filters to different interfaces or to whole classes of
  interfaces.
- `bpfCTLBLogFilter` is separate because CTLB programs run inside
  syscalls and have no packet to match against a pcap expression.
  The CTLB filter is effectively a boolean "do/don't log"
  per-CTLB-hook; the docstring in `config-params.json` notes that
  it must be `all` to see CTLB logs when `BPFLogFilters` is set,
  so that one knob doesn't accidentally silence the other.

### Review notes for this section

- A change that adds a new BPF sub-program to the path must add a
  matching `_DEBUG` variant in `enum cali_jump_index` and keep the
  fast/debug offset in `allocateLayout` consistent. Otherwise the
  debug path cannot reach the new program.
- Any change to `skb->cb[0]`/`skb->cb[1]` semantics must be
  reflected in the filter compiler's epilogue
  (`programFooter` in `filter.go`) — the filter and the main
  programs have to agree on which slot is "allow" and which is
  "deny/fast".
- A PR that introduces a new type of filter target (for example,
  filtering by metric rather than pcap expression) should reuse the
  dual-path loading scheme rather than inventing a new one. The
  machinery to load two path-variants of every sub-program is
  already there; duplicating it across filter types is how this
  area becomes unmaintainable.




## Flow logs & event ring buffer

### What it is, and what it is not

Flow logs are **per-flow events** (one event per flow start /
flow end / flow update), emitted by the BPF programs into a
ring buffer and consumed in userspace. They feed Calico's flow
log / observability pipeline (Goldmane and friends).

They are distinct from:

- **Debug log filters (Debug log filters)**, which emit per-packet textual
  traces for diagnosis. Log filters are off by default; flow
  logs are a feature.
- **BPF counters**, which produce aggregate counts, not
  per-flow records.

The names are similar — both come with "logs" in the config —
but the mechanisms share nothing. A reviewer touching one
should not assume changes propagate to the other.

### Enablement

Flow logs are gated globally by the `FLOWLOGS_ENABLED` flag
(`felix/bpf-gpl/bpf.h` / `globals.h`, bit
`CALI_GLOBALS_FLOWLOGS_ENABLED`). Set per-attach-type through
the `FlowLogsEnabled` field on the AttachPoint. When the flag
is off, the emission paths in the BPF programs are compiled to
no-ops via the runtime flag check; no per-packet cost.

### Emission path

The main BPF programs (`tc.c`) call the flow-log emit helpers
at well-defined flow events:

- **Flow start** — on creating a new CT entry (new allowed
  flow).
- **Flow end / close** — when conntrack deletes the flow,
  either via the scanner's expiry ([bpf-conntrack-flowstate.md → Conntrack & cleanup](./bpf-conntrack-flowstate.md)) or because a RST/FIN
  has been observed.
- **Denies and mid-flow policy verdicts** — when a packet is
  dropped for a policy reason we want recorded.

Events are written to a **BPF ring buffer**
(`felix/bpf-gpl/ringbuf.h`; userspace reader in
`felix/bpf/ringbuf/`) with a structured event header (see
`events.h` / `events_type.h` in `bpf-gpl`, consumed by
`felix/bpf/events/`). The event carries the 5-tuple, the
conntrack flags at the time of the event, packet and byte
counters, timestamps and a verdict code.

### Why ring buffer, not perf buffer

BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`, kernel 5.8+) is
preferred over the older per-CPU perf-event buffer for this
use because it is MPSC (multi-producer, single-consumer), so
the userspace side does not need to fan in from `nCPU`
readers, and it has the correct backpressure semantics
— drops are explicit and countable rather than per-CPU
reorderings. Calico's minimum kernel (5.10) supports it.

### Fast-path discipline

The emission sites are on the flow-creation path, not on every
packet of an established flow, so the per-packet fast-path cost
([bpf-overview.md → Fast-path performance discipline](./bpf-overview.md)) is unaffected when flow logs are on. The `FLOWLOGS_ENABLED`
branch that guards emission is also a single mark-style load,
which is acceptable on the fast path.

### Review notes

- A change to the event struct is a wire-format change between
  BPF and userspace. The reader in `felix/bpf/events/` and any
  downstream collector (Goldmane, syslog shipper) need to be
  updated in step.
- New event types go in `events_type.h` (new enum value) and
  need a handler on the reader side. Emitting an unknown type
  leaves it at "ignored" in userspace — silent data loss.
- A new emission _call site_ should be gated on
  `FLOWLOGS_ENABLED` so an operator who disables the feature
  does not pay for it.
- Do **not** emit events on every packet of an established
  flow. That turns a cheap feature into a fast-path regression
  ([bpf-overview.md → Fast-path performance discipline](./bpf-overview.md)). The established-flow path already does not, and it
  should stay that way.




## QoS

### Scope of BPF involvement

Calico's QoS controls cover bandwidth, packet rate, connection count
and DSCP. Not all of those live in BPF:

- **Bandwidth** is handled by tc qdiscs on the workload veth and by
  the upstream CNI bandwidth plugin. BPF is not involved.
- **Connection count** (`IngressMaxConnections` / `EgressMaxConnections`
  on a workload endpoint) is enforced via `*tables` rules — look for
  `LimitNumConnections` in `felix/rules/endpoints.go`. BPF is not
  involved.
- **Packet rate** is enforced by BPF (per-workload token bucket).
- **DSCP** marking is applied by BPF on egress to external
  destinations and HEPs.

The BPF-specific implementation lives under `felix/bpf/qos/` (Go) and
`felix/bpf-gpl/qos.h` (C).

### Packet rate

Packet rate is enforced per-interface, per-direction. The BPF map
`cali_qos` (`felix/bpf/qos/map.go`, key `(ifindex, ingress)`)
holds the TBF state per attach point. The value struct carries the
configured `packet_rate` (tokens/second) and `packet_burst` (bucket
size), plus mutable token count and the last-update timestamp,
protected by a BPF spinlock.

`qos_enforce_packet_rate` in `qos.h`:

- No entry in the map → no rate limit → accept.
- Under the spinlock: advance the token count based on elapsed time,
  cap at burst, decrement by one per accepted packet.
- No tokens → drop with `TC_ACT_SHOT`.

The per-direction `INGRESS_PACKET_RATE_CONFIGURED` /
`EGRESS_PACKET_RATE_CONFIGURED` flags (set on the AttachPoint and
propagated to BPF globals) let the program skip the map lookup
entirely when the feature isn't configured for that attach point.

### DSCP

DSCP marking is configurable via the `qos.projectcalico.org/dscp`
annotation on a HEP or WEP. The value is carried in BPF globals as
`EGRESS_DSCP` and applied on egress:

- On a new egress connection, if DSCP is configured and the
  destination is outside the cluster or on a HEP (see
  `cali_rt_flags_should_set_dscp` in `felix/bpf-gpl/routes.h`), the
  BPF program sets `CALI_CT_FLAG_SET_DSCP` on the conntrack reverse
  entry (`conntrack_types.h`).
- On every subsequent egress packet on that flow, `CALI_ST_SET_DSCP`
  is raised from the CT flag and `qos_dscp_set` rewrites the IP
  header:
  - IPv4: upper six bits of the TOS byte (checksum is recomputed).
  - IPv6: upper four bits of `priority` and the top two bits of
    `flow_lbl[0]` (traffic class = DSCP + ECN).

The ECN bits are preserved in both address families. Istio's DSCP
hook (for L7 mesh identification at connection setup) uses a second
global, `ISTIO_DSCP`; see Istio ambient mode integration for the integration.

### Review notes for this section

- A new BPF-enforced QoS field needs a slot in the `cali_qos` value
  struct. That struct contains a `bpf_spin_lock` at offset 0, which
  must stay at offset 0; its presence also means the map is a
  `BPF_MAP_TYPE_HASH` (not LRU/percpu/etc.). Do not relax those
  without a plan for concurrent access.
- Any change to packet-rate accounting must preserve the spinlock
  discipline: all reads and writes of `packet_rate_tokens` /
  `packet_rate_last_update` happen under the lock, and the drop
  decision is part of the atomic section. Dropping outside the lock
  allows overshoot.
- A change that extends DSCP marking to new paths (a new tunnel
  type, a new forwarded-packet case) must set `CALI_ST_SET_DSCP`
  based on the CT flag, _not_ on the globals alone — globals are a
  per-attach-point configuration, not a per-flow decision. The CT
  flag is what records the per-flow policy decision.
- If a feature is added that looks like it belongs in the QoS chain
  but only needs per-packet iptables-visible behaviour (e.g. a
  simple drop rule), prefer placing it in the `*tables` rule
  generators — `felix/rules/endpoints.go` already handles the
  connection-count and similar per-WEP knobs.




## Istio ambient mode integration

The BPF dataplane's only contribution to Istio ambient mode is
**marking the TCP SYN of a new flow between two mesh workloads
with a configurable DSCP** so ztunnel can recognise in-mesh
traffic at connection setup. Nothing else — no traffic redirection,
no ztunnel hosting, no HBONE — is in the BPF dataplane.

### BPF-side DSCP marking

On host-egress-to-WEP (`CALI_F_TO_WEP`), for TCP SYN packets only,
the main program in `tc.c` does:

1. Gate on `ISTIO_DSCP >= 0`. This per-interface global is `-1`
   by default and becomes the configured DSCP value only for
   WEPs that are mesh members, so the check vanishes for
   non-mesh interfaces.
2. Gate on `ct_result_is_syn(...)`. Established-flow packets
   skip the whole block; the fast path pays zero per-packet cost.
3. Look up the source IP in the `ALL_ISTIO_WEPS_ID` IP set
   (`RESERVED_IP_SET_BASE + 3` in `felix/bpf-gpl/policy.h`,
   shared with the Go constant `IPSetIDAllIstioWEPs` in
   `felix/rules/rule_defs.go`). This confirms the sender is also
   a mesh member.
4. On match, `qos_dscp_set(ctx, ISTIO_DSCP)` rewrites the DSCP
   bits in the IPv4 TOS / IPv6 traffic-class byte — same
   mechanics as QoS QoS DSCP.

The `ALL_ISTIO_WEPS_ID` IP set is populated by Felix with every
mesh WEP in the cluster (local and remote); it lives in the
regular shared BPF IP-set map, not a dedicated one.

### Per-endpoint on/off

The feature is gated at two levels:

- **Cluster-wide:** `IstioAmbientMode` in FelixConfig (default
  `Disabled`).
- **Per-endpoint:** per-interface, the attach-point global
  `ISTIO_DSCP` is set to `-1` for WEPs that are _not_ mesh
  members and to the configured DSCP value for WEPs that are.
  Felix decides per-WEP based on the
  `istio.io/dataplane-mode` label on the WEP's namespace or the
  WEP itself (with `=none` as an opt-out); the result is tracked
  as `hasIstioDSCP` in
  `felix/dataplane/linux/bpf_ep_mgr.go` and pushed into the
  attach-point globals when the program is (re)attached.

So the DSCP marking fires only when **both** the attached WEP is
a mesh member (gate via `ISTIO_DSCP >= 0`) **and** the source is
a mesh member (IP-set lookup). Neither side by itself triggers
the rewrite.

The DSCP value is configurable via `IstioDSCPMark` (default `23`,
a convention shared with Istio ztunnel).

### Review notes

- The SYN-only path is load-bearing. A change that moves Istio
  DSCP marking onto every packet breaks [bpf-overview.md → Fast-path performance discipline](./bpf-overview.md) fast-path discipline.
  If a future feature genuinely needs per-packet Istio DSCP,
  reuse `CALI_CT_FLAG_SET_DSCP` / `CALI_ST_SET_DSCP` from QoS
  rather than introducing a second per-packet rewrite.
- `ALL_ISTIO_WEPS_ID = RESERVED_IP_SET_BASE + 3` is shared
  between Go and C. A change to either side requires matching
  changes on the other.
- BPF unit test: `felix/bpf/ut/istio_test.go`.




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
