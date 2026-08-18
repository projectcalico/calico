---
applyTo:
  - "confd/pkg/backends/calico/bgp_processor.go"
  - "confd/tests/**"
  - "node/filesystem/etc/calico/confd/templates/**"
  - "felix/dataplane/linux/ipip_mgr*.go"
  - "felix/dataplane/linux/noencap_mgr*.go"
  - "felix/calc/encapsulation_resolver*.go"
  - "api/pkg/apis/projectcalico/v3/bgpconfig.go"
  - "api/pkg/apis/projectcalico/v3/felixconfig.go"
---

# Cluster route programming

A *cluster route* is the route one node needs to reach a workload
on another node. Either Felix or confd/BIRD programs it, chosen
per encapsulation type by the `programClusterRoutes` fields on
`FelixConfiguration` and `BGPConfiguration`. The architecture,
the ownership matrix, the supported combinations of the two
fields, the deprecation of BIRD-programmed IPIP routes, and the
per-section review notes live in
[`design/cluster-route-programming/DESIGN.md`](../../design/cluster-route-programming/DESIGN.md).

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`, read that design and apply the review notes embedded
in it. Follow links — it references the Felix sub-designs for the
dataplane and calc-graph architecture that the route managers sit
in.

The single most common way to get this wrong is to change one
side of the split and not the other: Felix and confd read
different resources, and a change that leaves them disagreeing
either double-programs a route or leaves it unprogrammed. Check
both.

## Update rule

[`design/MAINTAINING.md`](../../design/MAINTAINING.md) is the
canonical rule. **The default is no edit**, and an edit that does
belong is normally one to three lines in a section that is
already there.

Here, the changes that *usually* earn one are a change to which
component owns which encapsulation type, to the enum values or
defaults of either `programClusterRoutes` field, to the BIRD
kernel-programming filter, or to the deprecation and removal
plan. Treat that list as candidates, not as a trigger: the edit
is warranted only if a sentence in
`design/cluster-route-programming/DESIGN.md` is now false, or the
change introduces an invariant or a concept the doc does not
name.

**Exemption.** No doc update at all if the PR is exclusively one
of: (a) a bug fix that restores behavior the doc already
describes, (b) a mechanical refactor with no observable change,
(c) comment / log-message edits, (d) a dependency bump.
