<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Felix — Architecture & Design Index

Felix is Calico's per-node agent. It watches the datastore for
configuration, computes per-endpoint state through its calculation
graph, and programs one or more dataplanes (BPF, iptables,
nftables, Windows) to enforce policy and route traffic.

This document has two parts:

1. **Architecture overview** — the shape of Felix as a whole. Read
   this first; it sets the context every sub-design depends on.
2. **Sub-design index** — pointers to per-topic design docs under
   [`felix/design/`](./design/) with a path-to-doc mapping.
   Invariants and review criteria live in the sub-designs, not
   here.

Operational guidance (how to build, test, debug, use tooling) is
separate and lives in [`felix/CLAUDE.md`](./CLAUDE.md).

## 1. Architecture overview

### Data flow

```
Datastore syncer
   → AsyncCalcGraph
   → CalcGraph (dispatcher + calculation nodes)
   → EventSequencer
   → InternalDataplane
   → dataplane-specific managers → kernel objects
```

1. **Datastore syncer** receives updates from the Calico datastore
   (Kubernetes CRDs or etcd).
2. **`CalcGraph`** processes them through a graph of calculation
   nodes — policy resolution, route resolution, IP set indexing,
   service-endpoint synthesis, VTEP calculation, encapsulation mode.
3. **`EventSequencer`** buffers and coalesces the outputs and flushes
   them in dependency-safe order (e.g. IP sets before the policies
   that reference them).
4. The **dataplane driver** (`dataplane/driver.go`) selects a
   dataplane implementation based on configuration.
5. **`InternalDataplane`** (Linux; `dataplane/linux/int_dataplane.go`)
   or the Windows equivalent (`dataplane/windows/win_dataplane.go`)
   fans updates out to **managers**, each owning a slice of
   dataplane state.

Key orientation files: `daemon/daemon.go`, `calc/calc_graph.go`,
`dataplane/linux/int_dataplane.go`, `dataplane/driver.go`.

### Calculation graph (the "brain")

The calc graph in `felix/calc/` is an event-processing pipeline
that transforms raw datastore updates into dataplane-ready
instructions. Key calculation nodes:

| Node | Role |
|---|---|
| `AllUpdDispatcher` | Fans out datastore updates by resource type to downstream nodes |
| `ActiveRulesCalculator` | Tracks which policies/profiles are active based on endpoint labels |
| `RuleScanner` | Scans rules for selector references; feeds the IP-set index |
| `PolicyResolver` | Resolves per-endpoint policy ordering (tiers, priorities) |
| `L3RouteResolver` | Computes routes from IP pools, workload endpoints, and host IPs |
| `VXLANResolver` | Computes VTEP (VXLAN tunnel endpoint) entries |
| `EncapsulationResolver` | Determines encapsulation mode from IP-pool config |
| `IstioCalculator` | Marks WEPs in the Istio ambient mesh (see [bpf-dataplane §21](./design/bpf-dataplane.md)) |

`PipelineCallbacks` (`calc/calc_graph.go`) is the composite
interface the graph emits through. `EventSequencer`
(`calc/event_sequencer.go`) is the primary implementation —
it buffers updates in `pending*` maps/sets and flushes via
`Flush()` in dependency-safe order, coalescing rapid updates so
the dataplane only sees the final state.

Full invariants and per-node review notes will live in
`felix/design/calc-graph.md` when that sub-design is written.

### Dataplane manager pattern

Every dataplane (BPF, iptables, nftables, Windows) is structured
around a common **manager pattern**. A manager owns a slice of
dataplane state (endpoints, policy chains, IP sets, routes, etc.)
and implements:

```go
type Manager interface {
    OnUpdate(protoBufMsg any)
    CompleteDeferredWork() error
}
```

Extended interfaces: `ManagerWithRouteTables` (exposes route-table
syncers), `ManagerWithRouteRules` (exposes routing rules),
`UpdateBatchResolver` (pre-apply batch resolution).

Event loop (`InternalDataplane.loopKeepingDataplaneInSync` and
friends):

1. Receive protobuf messages from the calc graph.
2. Fan out via `OnUpdate()` to each registered manager.
3. Throttled `apply()` cycle: call `CompleteDeferredWork()` on
   each manager, then sync route tables and rules.

Managers are registered via `RegisterManager()`. Key managers:

| Manager | Handles |
|---|---|
| `endpointManager` / `bpfEndpointManager` | Workload/host endpoint programming |
| `policyManager` / `rawEgressPolicyManager` | Policy chain/rule generation |
| `ipsetsManager` | IP-set synchronisation |
| `noEncapManager` / `vxlanManager` | Route management for encap modes |
| `ipipManager` | IPIP tunnel interfaces |
| `wireguardManager` | WireGuard tunnel setup |
| `masqManager` | IP masquerade rules |
| `hostIPManager` | Host-IP tracking |
| `floatingIPManager` | Floating-IP NAT |
| `dscpManager` | DSCP marking |
| `serviceLoopManager` | Service-loop prevention |
| `failsafeMgr` | BPF failsafe port programming |

IPv4 and IPv6 each get their own manager instances.
`dataplane/driver.go` is the factory that constructs and wires
the dataplane.

### Dataplane backends

Felix runs against one dataplane at a time (selected by
`BPFEnabled` and `NFTablesMode` config):

- **BPF** — eBPF programs on TC and cgroup hooks, BPF maps for
  NAT / conntrack / policy. See
  [`design/bpf-dataplane.md`](./design/bpf-dataplane.md).
- **iptables** — legacy netfilter via `iptables-restore`. Code
  in `felix/iptables/`.
- **nftables** — modern netfilter via the nftables API. Code in
  `felix/nftables/`.
- **Windows** (HNS/HCN) — separate dataplane in
  `dataplane/windows/`.

The `iptables` and `nftables` backends share a common rule-
generation layer in `felix/rules/` and a common table-abstraction
interface in `felix/generictables/`. Backend-neutral rule
generation: `dispatch.go` (per-endpoint dispatch chains),
`policy.go` (policy chain generation), `endpoints.go` (endpoint
chain setup), `static.go` (boilerplate filter/NAT/mangle chains),
`nat.go`. A PR adding policy semantics usually touches
`felix/rules/` and needs matching changes on both backends.

### Shared networking subsystems

Used by more than one dataplane:

| Package | Purpose |
|---|---|
| `routetable/` | Linux route-table management via netlink |
| `routerule/` | Policy-based routing rules |
| `vxlanfdb/` | VXLAN forwarding-database management |
| `wireguard/` | WireGuard tunnel setup and key management |
| `ifacemonitor/` | Interface state monitoring (link up/down, address changes) |
| `nfnetlink/` | Conntrack and nflog via netfilter netlink |
| `netlinkshim/` | Netlink abstraction layer for testing and portability |

These will be covered in sub-designs (`route-sync.md`,
`flow-logs-collector.md`) as and when those are written.

## 2. Sub-design index

Per-topic design docs under [`felix/design/`](./design/). Each is
the authoritative source for its area's architecture, invariants,
and review notes.

A PR that touches files across multiple "applies to" scopes must
load **every** matching sub-design before acting. The `applies to`
column is the authoritative mapping from source path to design
doc.

The `bpf-*` rows form a single sub-design family for the BPF
dataplane, deliberately split so a PR touching one area pulls
only the relevant knowledge. The `bpf-overview` umbrella row is
the always-pulled foundation (packet-path mental model, fast-path
cost rule, cross-cutting review notes); the others have tight
`applyTo` globs scoped to their topic. **Load each of them either
when you touch a matched file or when you're working on the
related topic** — the globs cover the common cases, but a change
in a central file (e.g. `tc.c`, `bpf.h`) may legitimately need a
sub-design even if the immediate edit site doesn't match its glob
narrowly, and conversely a PR description that says "this fixes
the conntrack scanner" should pull `bpf-conntrack-flowstate.md`
even if the edit happens to land in code paths the glob doesn't
list. This is the worked example of the multi-file split pattern;
complex sub-designs in other areas (when they exist) should follow
the same shape if they grow large.

| Topic | Applies to | Status |
|---|---|---|
| [bpf-overview](./design/bpf-overview.md) | `felix/bpf/**`, `felix/bpf-gpl/**`, `felix/dataplane/linux/bpf_*.go`, `felix/dataplane/linux/vxlan_mgr.go` (umbrella — pulled by every BPF change) | ✅ exists |
| [bpf-tc-programs](./design/bpf-tc-programs.md) | `felix/bpf-gpl/tc.c`, `tc_preamble.c`, `xdp_preamble.c`, `jump.h`, `bpf.h`, `globals.h`, `types.h`, `felix/bpf/hook/**`, `felix/bpf/tc/**`, `felix/bpf/jump/**`, `felix/bpf/ifstate/**` | ✅ exists |
| [bpf-xdp](./design/bpf-xdp.md) | `felix/bpf-gpl/xdp.c`, `xdp_preamble.c`, `metadata.h`, `felix/bpf/xdp/**` | ✅ exists |
| [bpf-services](./design/bpf-services.md) | `felix/bpf/proxy/**`, `felix/bpf/nat/**`, `felix/bpf/consistenthash/**`, `felix/bpf-gpl/connect*.{c,h}`, `nat*.h`, `nat_lookup.h`, `maglev.h`, `ctlb*.h`, `sendrecv.h`, `felix/dataplane/linux/bpf_ep_mgr.go` | ✅ exists |
| [bpf-host-networking](./design/bpf-host-networking.md) | `felix/dataplane/linux/bpf_ep_mgr.go`, `dataplanedefs/dataplane_defs.go`, `felix/bpf-gpl/fib_co_re.h` | ✅ exists |
| [bpf-conntrack-flowstate](./design/bpf-conntrack-flowstate.md) | `felix/bpf/conntrack/**`, `felix/bpf-gpl/conntrack*.{c,h}`, `rpf.h`, `felix/bpf/allowsources/**`, `felix/rules/static.go` | ✅ exists |
| [bpf-encap-fragments-icmp](./design/bpf-encap-fragments-icmp.md) | `felix/bpf/ipfrags/**`, `felix/bpf-gpl/ip_v4_fragment.h`, `tc_ip_frag.c`, `icmp*.h`, `fib*.h`, `felix/bpf/routes/**`, `felix/dataplane/linux/vxlan_mgr.go` | ✅ exists |
| [bpf-observability](./design/bpf-observability.md) | `felix/bpf/filter/**`, `events/**`, `ringbuf/**`, `qos/**`, `felix/bpf-gpl/log.h`, `events*.h`, `qos.h`, `ringbuf.h` | ✅ exists |
| tables-dataplane | `felix/iptables/**`, `felix/nftables/**`, `felix/generictables/**`, non-BPF parts of `felix/rules/**`, non-BPF parts of `felix/dataplane/linux/` | *not yet written* |
| calc-graph | `felix/calc/**` | *not yet written* |
| route-sync | `felix/routetable/**`, `felix/routerule/**`, `felix/vxlanfdb/**` | *not yet written* |
| flow-logs-collector | `felix/collector/**` | *not yet written* |
| config-engine | `felix/config/**` | *not yet written* |
| windows-dataplane | `felix/dataplane/windows/**` | *not yet written* |

A missing sub-design means the area's invariants have not been
written down yet — not that the area has no constraints. Treat
absence as "read the code and ask"; do not assume anything goes.

## 3. For coding agents and reviewers

- **Follow links.** Every sub-design may reference sibling
  sub-designs, `.github/instructions/*.instructions.md` files,
  code, or external references. Load them. A design is a graph,
  not a single node.
- **Load what applies — by path or by topic.** The `applies to`
  globs above are the path-based trigger: if a PR touches both
  BPF and route-sync code, both sub-designs are needed. The
  topic of the change matters too — a PR described as "fixing
  the conntrack scanner" should pull
  `bpf-conntrack-flowstate.md` even if the edit happens to land
  only in a central file the glob covers under a broader
  umbrella. When in doubt, pull the topic-relevant sub-design.
- **Review notes are the checklist.** Each sub-design embeds
  per-section review notes describing the invariants a PR must
  respect. At write-time, respect them; at review-time, apply
  them.
- **Update rule.** A change to how Felix works in a given area
  must update the relevant file under
  [`felix/design/`](./design/) in the same PR — typically the
  sub-design covering the area. This index
  (`felix/DESIGN.md`) is also updated when the sub-design
  table, a `applies to` scope, or §1's architecture overview
  changes. Exemptions: (a) a bug fix that restores behaviour
  the doc already describes, (b) a mechanical refactor with no
  observable change, (c) comment or log-message edits, (d)
  dependency bumps. If in doubt, update. The path-scoped
  [`.github/instructions/*.instructions.md`](../.github/instructions/)
  files wire this rule into Copilot's automated review.

## 4. Adding a new sub-design

When a topic above graduates from *not yet written* to a real
doc:

1. Create `felix/design/<topic>.md`. Follow the shape of any
   existing sub-design (the BPF family is the worked example):
   narrative prose, architecture, per-section review notes at
   the end of each section, and a "keep this in sync" tail.
2. Update the sub-design index above: replace *not yet written*
   with a link to the new file and the ✅ exists marker.
3. Move any orientation content that belongs to the new
   sub-design out of this file into the new doc (most of the
   §1 architecture overview is cross-cutting and stays here).
4. Create a matching
   `.github/instructions/<topic>.instructions.md` with the
   `applyTo` globs from the table above plus a pointer to the
   new design doc. Keep it thin — see any of the
   `bpf-*.instructions.md` files as the template.

### When a sub-design grows too big, split it

A single sub-design that grows large enough to bloat AI-tool
context for narrow PRs (in practice: ~2000+ lines, ~25k+ tokens)
should split into **a family of focused files** the way the BPF
dataplane did:

- A short always-pulled `<topic>-overview.md` containing the
  mental model, the cost / discipline rules, and cross-cutting
  review notes.
- Per-area files (`<topic>-<area>.md`) covering specific feature
  groupings, each with a tight `applyTo` glob in its own
  `.github/instructions/<topic>-<area>.instructions.md`.

The multi-file family appears in this index as multiple rows,
all sharing the topic prefix. A PR touching multiple areas
matches multiple instruction files; only the union of the
matched sub-designs loads, not the whole family.
