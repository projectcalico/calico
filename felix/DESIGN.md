<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Felix — Design Index

Felix is Calico's per-node agent. It watches the datastore for
configuration, computes per-endpoint state through its calculation
graph, and programs one or more dataplanes (BPF, iptables, nftables,
Windows).

High-level pipeline:

```
Datastore syncer
   → AsyncCalcGraph
   → CalcGraph (dispatcher + calculation nodes)
   → EventSequencer
   → InternalDataplane
   → dataplane-specific managers → kernel objects
```

This file is an **index**, not a design doc. Felix is large enough
that its design content is split by topic into
[`felix/design/`](./design/). Each sub-design covers architecture,
invariants, and per-section review notes for one area, and is the
authoritative source for that area. Read the relevant sub-design(s)
before writing or reviewing a change.

Operational guidance (how to build, test, debug, use tooling) is
separate and lives in [`felix/CLAUDE.md`](./CLAUDE.md).

## Sub-designs

A PR that touches files across multiple "applies to" scopes must
load **every** matching sub-design before acting. The `applies to`
column is the authoritative mapping from source path to design
doc.

| Topic | Applies to | Status |
|---|---|---|
| [bpf-dataplane](./design/bpf-dataplane.md) | `felix/bpf/**`, `felix/bpf-gpl/**`, `felix/dataplane/linux/bpf_*.go`, `felix/dataplane/linux/vxlan_mgr.go`, BPF-specific parts of `felix/rules/static.go` | ✅ exists |
| tables-dataplane | `felix/iptables/**`, `felix/nftables/**`, non-BPF parts of `felix/rules/**`, non-BPF parts of `felix/dataplane/linux/` | *not yet written* |
| calc-graph | `felix/calc/**` | *not yet written* |
| route-sync | `felix/routetable/**`, `felix/routerule/**`, `felix/vxlanfdb/**` | *not yet written* |
| flow-logs-collector | `felix/collector/**` | *not yet written* |
| config-engine | `felix/config/**` | *not yet written* |

A missing sub-design means the area's design content has not been
written down yet, not that the area has no constraints. Treat
absence as "read the code and ask"; do not assume anything goes.

## For coding agents and reviewers

- **Follow links.** Every sub-design may reference other docs —
  sibling sub-designs, `.github/instructions/*.instructions.md`
  files, code, or external references. Load them. A design is a
  graph, not a single node.
- **Load what applies.** If a PR touches both BPF and route-sync
  code, you need both sub-designs in context. The `applies to`
  globs above tell you which.
- **Review notes are the checklist.** Each sub-design embeds
  per-section review notes describing the invariants a PR must
  respect. At write-time, respect them; at review-time, apply
  them.
- **Update rule.** A change to how Felix works in a given area
  must update the relevant sub-design in the same PR. Exemptions:
  (a) a bug fix that restores behaviour the doc already
  describes, (b) a mechanical refactor with no observable
  change, (c) comment or log-message edits, (d) dependency
  bumps. If in doubt, update the doc. The path-scoped
  [`.github/instructions/*.instructions.md`](../.github/instructions/)
  files wire this rule into Copilot's automated review.

## Adding a new sub-design

When a topic above graduates from *not yet written* to a real
doc:

1. Create `felix/design/<topic>.md`. Follow the shape of
   `bpf-dataplane.md`: narrative prose, architecture, per-section
   review notes at the end of each section, a cross-cutting
   review-notes section at the bottom, and a "keep this in sync"
   bullet.
2. Update the table above: replace *not yet written* with a link
   to the new file and the ✅ exists marker.
3. Create a matching `.github/instructions/<topic>.instructions.md`
   with the `applyTo` globs from the table above plus a pointer
   to the new design doc. Keep it thin — see the BPF file as the
   template.

## Out of scope for this index

- Cross-component designs (e.g. the Felix↔dataplane protobuf
  protocol, which is shared with consumers outside Felix): those
  live elsewhere. Added when and if the need arises.
- User-facing documentation: see the Calico docs site and the
  Felix config reference (`felix/docs/config-params.md`).
