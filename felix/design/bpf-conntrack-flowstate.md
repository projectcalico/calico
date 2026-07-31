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

# eBPF dataplane — Conntrack and flow state

How flows are validated, recorded, and transitioned in BPF: BPF-side reverse-path filtering (RPF), the conntrack table with its forward/reverse pair convention and three-stage cleanup, the mid-flow fallthrough that lets BPF take over from `*tables` without breaking established connections, and the SkipFIB cooperation rule that makes 3rd-party DNAT in `*tables` interoperate with the BPF dataplane.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. The full set of sub-designs is
listed in [`felix/DESIGN.md`](../DESIGN.md).

## Reverse-path filter (RPF)

### Why RPF is in BPF

A large part of Calico's packet handling involves forwarding packets
directly with `bpf_redirect`, which bypasses the kernel's RPF check.
The kernel's per-interface `rp_filter` sysctl is also relaxed or
disabled on several Calico-managed interfaces — bpfnat, tunnel
devices — because the kernel would otherwise reject packets that
Calico has intentionally routed via unusual paths ([bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md)).

The result is that the kernel cannot be trusted to enforce RPF for
Calico traffic. BPF therefore does it directly. See
`felix/bpf-gpl/rpf.h`.

### WEP RPF

For packets arriving on a workload veth, the check is simple and
always strict: look up the source IP in the BPF route table; the
route must point at the same workload interface the packet arrived
on, and the target must be a local workload. `wep_rpf_check` in
`rpf.h`.

Spoofing can be allowed per-(ifindex, source-IP) via the AllowSources
map when `WORKLOAD_SRC_SPOOFING_CONFIGURED` is set. When the check
passes via that bypass, the flag `CALI_ST_SUPPRESS_CT_STATE` is set
so that the conntrack entry isn't created with a bogus source — an
explicit decision to accept the packet but not to build a flow
record around it.

### HEP RPF

Host-endpoint RPF has to cope with the general routing table and so
cannot simply compare ifindices. `hep_rpf_check` uses the BPF FIB
helper with the source and destination swapped: if the FIB succeeds,
the packet has a valid reverse route; if the ifindex on that reverse
route equals the arrival ifindex, the check is strict-ok; otherwise
it is loose-ok (accepted in loose mode, rejected in strict mode).

RPF mode is a per-interface setting set by the `RPFEnforceOption`
field on the attach point and carried to BPF via the
`CALI_GLOBALS_RPF_OPTION_ENABLED` and `CALI_GLOBALS_RPF_OPTION_STRICT`
flags.

Special cases:

- ICMPv6: bypasses RPF (link-local traffic is essential for IPv6
  operation and wouldn't survive strict checks).
- Link-local source with host-local destination is accepted
  (DHCP-style address resolution).

### Why the kernel's rp_filter is relaxed

Running with loose BPF RPF on top of strict kernel RPF is not safe —
when `rp_filter` is non-zero on an interface that matters, the
kernel applies its own RPF _before_ BPF's, and can drop a packet that
BPF intended to accept on one of the indirect routing paths. The
bpfnat veth ([bpf-host-networking.md → Host-networked workaround (bpfnat veth)](./bpf-host-networking.md)), the tunnel devices, and similar "packet arrives on
interface X but we expect the source to be routable via Y" paths all
depend on the kernel not second-guessing BPF.

Felix explicitly sets `net.ipv4.conf.all.rp_filter = 0` when the
bpfnat feature is enabled; per-interface sysctls are set to loose
(`2`) on interfaces where Calico forwards packets that may appear
misrouted to the kernel. BPF does the real check.

### Review notes for this section

- A change that makes a new interface type Calico-managed must decide
  whether BPF RPF needs to run on it, and set `RPFEnforceOption`
  accordingly. The default (RPF on) is right for most HEPs; tunnel
  interfaces and bpfnat need bespoke handling.
- Any change that needs the kernel to _not_ second-guess a BPF
  routing decision must relax the relevant `rp_filter` sysctl.
  Setting `all.rp_filter = 1` anywhere else in the codebase breaks
  bpfnat and tunnel paths.
- A change that bypasses RPF — for example, a new allow-source
  mechanism — should go through the same `CALI_ST_SUPPRESS_CT_STATE`
  path so that the conntrack table does not fill up with entries
  keyed on spoofed addresses.




## Conntrack & cleanup

### Entry shapes

The BPF conntrack table (`cali_v4_ct`, `cali_v6_ct`) holds three kinds
of entry (`TypeNormal`, `TypeNATForward`, `TypeNATReverse` in
`felix/bpf/conntrack/map.go`):

- **Normal.** Non-NAT'd flows. One entry per flow, keyed by the
  5-tuple. Covers both directions.
- **NAT forward.** The pre-NAT view of a NAT'd flow. Keyed on the
  pre-NAT 5-tuple; value contains the reverse key to look up the NAT
  backend state.
- **NAT reverse.** The post-NAT view. Keyed on the post-NAT 5-tuple;
  carries the NAT service details (backend, source-port rewrite,
  flags like `CALI_CT_FLAG_SVC_SELF`, `CALI_CT_FLAG_MAGLEV`).

Creating a NAT'd flow means creating both. Destroying a NAT'd flow
means destroying both — atomically enough that BPF never sees only
one side. The cleanup pipeline is built around this requirement.

### Cleanup: three layers

#### 1. Userspace scanners

A periodic sweep in Felix iterates the conntrack map and runs each
entry through a chain of `EntryScanner` instances
(`felix/bpf/conntrack/scanner.go`, scanners in
`felix/bpf/conntrack/cleanup.go`):

- **`LivenessScanner`** — reads the entry's timestamp and per-protocol
  timeout (`timeouts.Timeouts`), marks expired entries for deletion.
  For NAT'd flows, bookkeeping lives on the reverse entry — the
  forward-entry scanner follows the reverse-key pointer and decides
  based on the reverse entry's timestamp. A forward entry with no
  reverse counterpart is deleted immediately (it is useless without
  the reverse).
- **`StaleNATScanner`** — for each NAT'd flow, checks whether the
  service frontend still has the chosen backend. UDP stale-NAT
  entries are deleted from userspace immediately, because
  subsequent packets on the same flow would otherwise be forwarded
  to a dead backend.
- **`WorkloadRemoveScannerTCP`** — receives workload-IP-removed
  events from the BPF endpoint manager and, on the next sweep, marks
  TCP flows involving those IPs for **TCP reset** rather than silent
  deletion. The next packet on the flow triggers Felix to emit an
  RST, so clients see the connection drop immediately rather than
  hanging until the TCP timeout.

The scanners return a `ScanVerdict` per entry:
`ScanVerdictOK`, `ScanVerdictDelete`, `ScanVerdictSendRST`.

#### 2. BPF cleaner

Deleting entries directly from userspace is slow and creates a window
where the forward entry is gone but the reverse is not (or vice
versa). Felix therefore uses a BPF cleaner program
(`felix/bpf-gpl/conntrack_cleanup.c`, `BPFProgCleaner` in
`felix/bpf/conntrack/bpf_scanner.go`) for the common expired-entry
case:

- When the userspace liveness scanner marks an entry for deletion,
  Felix inserts a record into the **conntrack cleanup map**
  (`cali_ct_cleanup`, version `cleanupv1`). For a non-NAT entry the
  record's forward and reverse keys are the same; for a NAT entry
  the record captures _both_ keys and _both_ timestamps.
- Every N entries (currently 1000), Felix runs the BPF cleaner
  program. The program iterates the cleanup map, re-reads the
  corresponding conntrack entries, and deletes them only if the
  timestamps still match the recorded timestamps. This races safely
  with traffic that might have refreshed the flow: if the entry has
  been touched since being marked, the timestamp differs and the
  cleaner leaves it alone.
- NAT forward and reverse are deleted in the same program
  invocation, so the "only one side present" window is bounded by
  the cleaner program's execution (microseconds), not the userspace
  iteration.

#### 3. LRU fallback

The conntrack maps use an LRU hash backing, so if both the userspace
scanners and the BPF cleaner fall behind and the map fills, the
kernel evicts the oldest entries. This is a last-resort safety net,
not a primary cleanup path — losing an active flow's CT entry
produces a very visible application-level failure, so normal
operation should never rely on it.

### Timestamps

Conntrack entries carry kernel-time (`CLOCK_MONOTONIC`) timestamps
set by the BPF programs. Userspace caches the kernel-time translation
to avoid a per-entry `clock_gettime` overhead
(`LivenessScanner.goTimeOfLastKTimeLookup`). Any change to how
timestamps are stored needs to match on both sides — the BPF write
and the Go-side reader must agree on units and reference clock.

### Review notes for this section

- A new conntrack entry field needs a map-version bump
  (`cali_v4_ct`/`cali_v6_ct` have `Version: 4` at the time of
  writing). The kernel refuses to pin two layouts under the same
  name, and older Felixes reading a newer map will misparse.
- A new scanner should return the smallest verdict that does the job
  (`ScanVerdictOK` for no-op) and should be idempotent across
  iterations. Scanners may be called once or many times per sweep
  depending on how much Felix batches.
- A change to NAT-forward/reverse bookkeeping must preserve the
  invariant that both sides are deleted together. Either use the
  BPF cleaner path (insert into `cali_ct_cleanup`) or accept the
  race (and document why it is safe) — never delete a single side
  from userspace.
- Do not rely on LRU eviction to keep the table healthy. A PR that
  produces more conntrack entries per second than the cleanup
  pipeline removes will silently lose active flows once the map
  fills.




## Switching from `*tables` to eBPF

### What breaks on the switch

When a running cluster switches Felix's dataplane from `*tables` to
BPF, three kinds of flow are at risk:

- **Flows established before BPF was ever loaded.** The BPF conntrack
  table is empty, so a mid-flow packet will miss.
- **Flows established before Calico was installed.** Same as above —
  Calico typically honours pre-existing connections in `*tables`
  mode, and users expect the switch not to break that.
- **Flows whose kernel conntrack was pinned to a device that BPF
  recreates.** The VXLAN device recreation ([bpf-encap-fragments-icmp.md → VXLAN in eBPF mode](./bpf-encap-fragments-icmp.md)) is the clearest
  example: the tear-down drops kernel CT state for flows through
  that device, and they cannot be recovered.

Calico handles the first two with the "mid-flow fallthrough" pattern.
The third is unavoidable and is accepted as a cost of the switch.

### Mid-flow TCP fallthrough

TCP is stateful: a non-SYN packet with no BPF conntrack hit is
unambiguously a mid-flow packet. BPF and `*tables` cooperate to let
it through:

- On host ingress, a BPF program that sees a mid-flow TCP miss sets
  `CALI_SKB_MARK_FALLTHROUGH` on the packet (`bpf.h` enum
  `calico_skb_mark`) and returns `TC_ACT_UNSPEC`, letting the packet
  continue into netfilter.
- Felix installs a rule
  (`InternalDataplane.bpfMarkPreestablishedFlowsRules` in
  `int_dataplane.go`) that matches packets on their Linux conntrack
  state (ESTABLISHED/RELATED) and sets
  `CALI_SKB_MARK_CT_ESTABLISHED`
  (`MarkLinuxConntrackEstablished` = `0x08000000` in
  `felix/bpf/tc/defs/defs.go`).
- On the next TC hook the packet hits (for example, the host-egress
  program on the destination workload's veth), BPF sees the
  `CT_ESTABLISHED` mark and lets the packet through without
  re-running policy — the fact that Linux conntrack matched is
  evidence that the flow was previously vetted.

This gives correct behaviour for pre-existing flows as long as Linux
conntrack still has their state. It also preserves connections that
pre-date the Calico install entirely: same mechanism.

### UDP has no mid-flow

UDP does not signal flow establishment in the protocol, so BPF
cannot distinguish "a packet from a long-running UDP flow" from "a
fresh datagram". Any UDP packet that misses BPF CT is treated as new.
If the previous `*tables` dataplane had NAT'd the flow to a specific
backend, the BPF dataplane may now pick a different backend on first
sight. For protocols that care about backend affinity this manifests
as a brief disruption. The reference design document accepts this as
a valid tradeoff given UDP's delivery semantics; there is no
fallthrough shim for UDP.

### Operator coordination

Operator-based installs minimise the mixed-mode window by:

- Rolling out the BPF-capable Felix image via the normal rolling
  update.
- Once all nodes are running the new image, flipping the Felix
  configuration to enable BPF so every Felix switches more or less
  simultaneously.

During the mixed window, BPF nodes and `*tables` nodes coexist and
inter-node traffic uses the `*tables` dataplane path (since the BPF
node's encap/decap expects its peer to understand the BPF wire
format, which `*tables` doesn't).

### Review notes for this section

- A change to the mid-flow fallthrough path must preserve two
  invariants: (a) every mid-flow TCP miss on host ingress gets the
  `FALLTHROUGH` mark, and (b) every subsequent BPF program that
  sees a packet with `CT_ESTABLISHED` treats it as approved. Break
  either and the switch starts dropping existing TCP connections.
- A new rule generator for either iptables or nftables that emits
  the "mark pre-established flows" rule must keep the mark value
  (`0x08000000`) in sync with `MarkLinuxConntrackEstablished` in
  `felix/bpf/tc/defs/defs.go`. The mask must include that bit
  _and_ not overlap with any other BPF-owned mark.
- A change that adds BPF connection-establishment handling for
  UDP must not weaken the BPF-side handling of a UDP packet as
  independently processable — UDP applications tolerate packet loss
  but not out-of-order NAT rewrites on an existing flow.




## 3rd-party DNAT on host traffic

### What users want

Sometimes another agent on the host installs iptables/nftables DNAT
rules to redirect traffic addressed to a host port to a workload
port. A typical shape:

- Client sends `C:* -> H:hp` (H = host, hp = host port).
- Host DNAT rewrites destination: `C:* -> W:wp` (W = local workload,
  wp = workload port).

Without BPF this is straightforward: the packet hits the nat
PREROUTING chain, gets DNAT'd, and is routed to the workload. Return
traffic hits the nat POSTROUTING SNAT and the client sees the reply
from `H:hp`.

### Why it doesn't "just work" with BPF

Two problems:

1. **BPF FIB lookup bypasses netfilter.** When BPF's FIB-based
   forwarding succeeds, the packet is redirected directly to the
   workload veth and netfilter never runs — including the 3rd-party
   DNAT rule.
2. **Calico NOTRACK rules.** Calico's `*tables` raw-PREROUTING rules
   set NOTRACK on workload traffic (this is how BPF takes over from
   kernel conntrack). Kernel NAT requires tracked connections, so
   a DNAT rule that would otherwise match gets skipped.

### The fix: SkipFIB

Calico's raw-PREROUTING setup in
`felix/rules/static.go` (search for `MarkSeenSkipFIB`) installs a
rule that sets the **SkipFIB** skb mark on any packet whose
destination is the local host:

```
match: destination addrtype=LOCAL
action: set mark 0x01100000/0x01100000  (CALI_SKB_MARK_SKIP_FIB)
comment: "Mark traffic towards the host - it is TRACKed"
```

The mark is `tcdefs.MarkSeenSkipFIB`, which equals
`CALI_SKB_MARK_SKIP_FIB` on the BPF side
(see `felix/bpf-gpl/bpf.h` `enum calico_skb_mark`). Because this
happens in raw-PREROUTING, it runs _before_ any DNAT chain, so the
destination is still the host IP at match time.

What this buys:

- The packet is left TRACKed (Calico's NOTRACK rule doesn't apply to
  local-dest traffic), so any 3rd-party DNAT rule in nat-PREROUTING
  can match and rewrite the destination normally.
- Once the packet reaches BPF at the workload veth's ingress, the
  BPF program sees the `SKIP_FIB` mark and, on conntrack entry
  creation, copies it into the CT entry as
  `CALI_CT_FLAG_SKIP_FIB` (defined in
  `felix/bpf-gpl/conntrack_types.h`, mirrored in
  `felix/bpf/conntrack/v4/map.go` as `FlagSkipFIB`).
- Reply packets hit the CT entry, see the flag, and are routed via
  the host stack rather than `bpf_redirect`'d — so the host nat
  POSTROUTING chain (including Calico's own MASQ and the 3rd-party
  SNAT counterpart) runs normally.

### Review notes for this section

- The raw-PREROUTING rule is the _only_ place the SkipFIB mark is
  set by `*tables`. Changes to the rule-generator layer must keep
  this rule and must keep its `addrtype=LOCAL` match — a broader
  match unnecessarily forces the host stack for traffic that BPF
  could forward, a narrower match breaks 3rd-party DNAT.
- `CALI_CT_FLAG_SKIP_FIB` must be preserved on conntrack writes that
  refresh or update an entry. Losing the flag on a subsequent packet
  would re-enable FIB for the return leg and break the 3rd-party
  DNAT's return path.
- A change that introduces a new BPF mark in the `0x01100000`
  region must confirm it doesn't overlap with `SKIP_FIB` or the
  other bits the raw-PREROUTING rule sets — the whole mark word
  is routed back into BPF.




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
