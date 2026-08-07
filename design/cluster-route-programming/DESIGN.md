<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Cluster route programming — Architecture & Design

A **cluster route** is the route that one node needs in order to reach a workload running on a
different node.  It is often a route to a remote node's IPAM block, rather than to an individual
workload, and in that case the route exists on every node except the one that owns the block.  But
for OpenStack, which doesn't have node-affine blocks, and in Kubernetes when a workload IP is
borrowed from another node's block, a cluster route can also be to the specific /32 or /128 workload
IP.

Two components in the product can program cluster routes, and which one does is
configurable per encapsulation type:

- **Felix** computes them in its calculation graph and programs them through its
  route tables, alongside all the other routes it owns.
- **confd + BIRD** learn them over BGP and let BIRD write them to the kernel.

This design lives here, rather than under `felix/` or `confd/`, because the
choice is a single decision split across two components, two API resources, and
the node container's BIRD templates.  Getting either half wrong leaves a cluster
with no cluster routes, or with two components fighting over the same ones.

## 1. The ownership matrix

There are three classes of non-VXLAN, non-WireGuard IP Pool, and the owner of
each class is determined as follows.

| IP Pool                                               | Owner                   | Configurable?     |
|-------------------------------------------------------|-------------------------|-------------------|
| `vxlanMode: Always` or `CrossSubnet`                  | Felix                   | No — always Felix |
| `ipipMode: Always` or `CrossSubnet`                   | Felix by default        | Yes               |
| `ipipMode: Never` and `vxlanMode: Never` ("no-encap") | confd + BIRD by default | Yes               |

WireGuard is a further overlay on top of the above rather than a pool mode: when
the local node and a peer both run WireGuard, Felix routes to that peer over the
WireGuard device and confd emits a BIRD kernel-filter reject for it
(`processWireguardPeerFilter` in `confd/pkg/backends/calico/bgp_processor.go`).

### The two configuration fields

The choice is expressed twice, once per component, because Felix and confd read
different resources:

- `FelixConfiguration.spec.programClusterRoutes` — which classes **Felix**
  programs.  Default `EnabledIPIPOnly`.
- `BGPConfiguration.spec.programClusterRoutes` — which classes **BIRD**
  programs.  Default `EnabledNoEncapOnly`.

Both fields take the same four values, and each value names the set of classes
that component is responsible for:

| Value                | IPIP pools | No-encap pools |
|----------------------|------------|----------------|
| `Disabled`           | no         | no             |
| `EnabledIPIPOnly`    | yes        | no             |
| `EnabledNoEncapOnly` | no         | yes            |
| `Enabled`            | yes        | yes            |

The two fields are independent, so the operator (human or `tigera/operator`) is
responsible for keeping them complementary.  The supported combinations are:

| FelixConfiguration   | BGPConfiguration     | Result                                                              |
|----------------------|----------------------|---------------------------------------------------------------------|
| `EnabledIPIPOnly`    | `EnabledNoEncapOnly` | **The default from v3.33.** Felix owns IPIP, BIRD owns no-encap.    |
| `Enabled`            | `Disabled`           | Felix owns everything; BIRD programs no cluster routes.             |
| `Disabled`           | `Enabled`            | The pre-v3.33 default.  BIRD owns everything.  Deprecated for IPIP. |
| `EnabledNoEncapOnly` | `EnabledIPIPOnly`    | Felix owns no-encap, BIRD owns IPIP.  Deprecated for IPIP.          |

Any other pairing either double-programs a class (both components fight over the
same CIDRs, and the route flaps) or leaves a class unprogrammed (no cluster
connectivity for pods in those pools).  Nothing in the product detects or
rejects an inconsistent pair; see the review notes below.

### Who sets the fields

In a manifest-installed cluster the defaults above are what a cluster gets,
because nothing writes the fields.

In an operator-installed cluster, `tigera/operator` derives both fields from
`Installation.spec.calicoNetwork.clusterRoutingMode` — but only when that field
is set.  When it is unset, which is the common case, the operator writes neither
field, so the defaults above are what the cluster gets.  Changing a default here
therefore reaches operator-installed clusters too, and does so on upgrade.

`clusterRoutingMode` was a single `BIRD` / `Felix` choice, which cannot express
the split; tigera/operator#5150 adds a `FelixIPIPOnly` value that maps onto the
complementary pair in the table above.  A change to either field's default or
enum needs a matching `tigera/operator` PR and the `needs-operator-pr` label.

### Review notes — §1

- A change to either enum must change both, and must keep the values meaning
  the same thing on both sides.  The symmetry is the only thing that makes the
  combination table above readable.
- Do not add a `+kubebuilder:default` marker to either field.  A CRD default is
  materialised into the stored object on write, which would pin the value and
  stop a future release from moving the default again — and the default *is*
  expected to move again (see §5).  The etcd datastore has no CRD defaulting at
  all, so the code-level default in each component is load-bearing regardless.
- Both components must default the same way when the field is absent *and* when
  it holds a value they do not recognise, so that a cluster mid-upgrade, or one
  whose CRDs are newer than its binaries, does not end up with two components
  that disagree.

## 2. Code map

### Felix

| Location                                 | Role                                                                                                                                                                                                                                                                               |
|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `felix/config/config_params.go`          | `ProgramClusterRoutes` param (`oneof`, default `EnabledIPIPOnly`) and the `ProgramIPIPClusterRoutes()` / `ProgramNoEncapClusterRoutes()` accessors.  Nothing outside config should compare the raw string.                                                                         |
| `felix/calc/encapsulation_resolver.go`   | `NoEncapEnabled()` folds `ProgramNoEncapClusterRoutes()` into the encap summary: it means "there are unencapsulated pools *and* Felix owns their cluster routes".  `IPIPEnabled()` does **not** fold ownership in, because the IPIP tunnel device is Felix's to manage either way. |
| `felix/calc/calc_graph.go`               | Gates construction of the `L3RouteResolver` on there being some encapsulation whose routes Felix owns.                                                                                                                                                                             |
| `felix/dataplane/driver.go`              | Copies the two booleans into the dataplane `Config`.                                                                                                                                                                                                                               |
| `felix/dataplane/linux/int_dataplane.go` | `ProgramIPIPClusterRoutes` / `ProgramNoEncapClusterRoutes`; the no-encap managers are only created when Felix owns no-encap.                                                                                                                                                       |
| `felix/dataplane/linux/ipip_mgr.go`      | The IPIP manager always runs (it owns `tunl0`), but only feeds its route manager when Felix owns IPIP cluster routes.                                                                                                                                                              |

The asymmetry between IPIP and no-encap in Felix is deliberate and worth
restating: `noEncapManager` exists *only* to program cluster routes, so it is
not created at all when BIRD owns them; `ipipManager` also configures and
monitors the tunnel device, so it always exists and instead gates its route
programming internally.

### confd + BIRD

| Location                                                            | Role                                                                                                                                                                                                          |
|---------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `confd/pkg/backends/calico/bgp_processor.go`                        | `clusterRoutePolicy` and `clusterRoutePolicyFromBGPConfig` parse the BGPConfiguration field; `processIPPool` decides, per pool, whether BIRD's kernel-programming filter accepts or rejects that pool's CIDR. |
| `node/filesystem/etc/calico/confd/templates/bird_ipam.cfg.template` | Renders `filter calico_kernel_programming` from those statements, plus `calico_export_to_bgp_peers`.                                                                                                          |

Only the *kernel-programming* filter varies with ownership.  The
export-to-peers filters are the same either way, because whether this node
should advertise a prefix to its peers is a separate question from who writes
the route to this node's kernel.

For an IPIP pool that BIRD owns, the filter statement also sets BIRD's
`krt_tunnel` variable, which tells the kernel protocol to send the route out
`tunl0`.  `krt_tunnel` does not exist in upstream BIRD — it is the reason
Calico ships a BIRD fork (`projectcalico/bird`, pinned as `BIRD_VERSION` in
`metadata.mk`).  Retiring BIRD-programmed IPIP cluster routes is therefore also
what retires the fork.

### Review notes — §2

- Felix must never compare `config.ProgramClusterRoutes` directly outside
  `felix/config`; use the two accessors, so that adding a value later is a
  one-file change.
- `NoEncapEnabled` conflating "pools exist" with "Felix owns them" is a trap
  for new code.  If you need "unencapsulated pools exist" irrespective of
  ownership, add a separate accessor rather than un-conflating this one — the
  encap summary is compared field-by-field to decide whether Felix must restart
  (`encapsulation_resolver.go`), and changing what a field means changes when
  Felix restarts.
- confd renders both the IPv4 and IPv6 templates from the same policy.  IPIP is
  IPv4-only in practice, but `processIPPool` must not assume that: it keys off
  the pool's `ipipMode`, not the IP version.

## 3. Deprecation of BIRD-programmed IPIP cluster routes

As of **v3.33**, having BIRD program the cluster routes for IPIP pools is
deprecated.  Concretely, the deprecated configurations are
`BGPConfiguration.programClusterRoutes` = `Enabled` or `EnabledIPIPOnly`, and
equivalently `FelixConfiguration.programClusterRoutes` = `Disabled` or
`EnabledNoEncapOnly`, in a cluster that has IPIP pools.

The intent is to remove the ability entirely in **v3.35**, at which point:

- `krt_tunnel` support can be dropped from the BIRD config templates, and the
  `projectcalico/bird` fork can be retired in favour of upstream BIRD.
- The `EnabledIPIPOnly` value of `BGPConfiguration.programClusterRoutes`, and
  the `Disabled` / `EnabledNoEncapOnly` values' effect on IPIP, become
  no-ops or are removed.

Users on the deprecated path are told at runtime: confd logs a warning on every
render in which BIRD is configured to program the cluster routes of at least one
IPIP pool.

Neither API field is itself deprecated — it is a *configuration* that is going
away, not a field.  That is why the field doc comments say "Note:" rather than
"Deprecated:": the latter is a Go convention that marks the whole symbol, and
would make staticcheck flag every read of the field.

This deprecation sits inside a wider decision not to do further work on IPIP for
new features — in particular, IPIP is not expected to gain support for KubeVirt
live migration.  That is why the IPIP default is being moved on its own, ahead
of no-encap.

### Review notes — §3

- The deprecation warning is per-render, not per-node-lifetime.  Do not
  "improve" it into a once-only log: users grep for it, and confd re-renders
  rarely enough that the volume is not a problem.
- Do not extend the deprecation to no-encap.  BIRD-programmed no-encap cluster
  routes remain fully supported, and are still required for the dual-ToR
  topology (§5).

## 4. Transitioning a running cluster

On upgrade to v3.33, a cluster with IPIP pools and no explicit configuration
moves from BIRD-programmed to Felix-programmed IPIP cluster routes.  The
handover is:

1. confd sees the new default and re-renders `bird_ipam.cfg` so that
   `calico_kernel_programming` rejects the IPIP pools' CIDRs.
2. BIRD reloads and withdraws those routes from the kernel, because they were
   BIRD's own routes and BIRD is no longer exporting them.
3. Felix, in the same window, starts programming the same CIDRs with its own
   route protocol (`DeviceRouteProtocol`, default 80).

Steps 2 and 3 are not synchronised, so a route may be briefly absent or briefly
present twice.  Both components converge on the same next hop and device, so
the window is a reordering rather than a blackhole in practice — but it is
unmeasured, and a cluster that cannot tolerate any cross-node packet loss should
be upgraded with the pre-v3.33 configuration pinned explicitly, then switched
over deliberately.

If BIRD is stopped before it withdraws its routes (for example, if the node
container is killed mid-upgrade), stale `proto bird` routes can be left behind.
Felix's route-ownership heuristic does not claim them, so they persist until
BIRD next runs.  Making Felix adopt and clean up BIRD's IPIP routes is a
possible future improvement; it is not implemented.

### Review notes — §4

- Any change to the handover must keep the property that *both* components
  reach the same conclusion from the same datastore state.  The only reason the
  window is short is that confd and Felix are reacting to the same change at the
  same time; introducing a staged or operator-driven migration would need the
  intermediate state to be explicitly representable in the API, not implied.

## 5. Known gaps

These are recorded so that a future change does not mistake them for solved
problems.

**Felix-programmed cluster routes and BGP re-advertisement.**  BIRD's kernel
protocol is configured with `learn`, so it learns alien kernel routes —
including the cluster routes Felix programs.  `calico_export_to_bgp_peers`
rejects the ones that leave via a Calico tunnel device matching `*.cali` /
`*.calico` (VXLAN, WireGuard), and only for internal peers.  Felix-programmed
IPIP routes leave via `tunl0` and Felix-programmed no-encap routes leave via an
ordinary NIC, so neither is caught: a node can end up advertising other nodes'
blocks to its peers.  This predates the change of default — it already applies
to Felix-programmed no-encap routes — but changing the IPIP default makes it the
default path for IPIP clusters with BGP peers.  It has not been reproduced or
measured, and no fix is implemented.  Any fix needs to distinguish "route this
node owns" from "route this node learned or synthesised", which the current
ifname-matching heuristic cannot do in general.

**KubeVirt live migration.**  Route-priority propagation for live migration was
designed and tested for confd/BIRD-programmed routes.  Whether the elevated
priority is programmed correctly when *Felix* programs the remote routes has not
been verified.  For IPIP this is out of scope by decision (no new-feature work
on IPIP); for no-encap and VXLAN it is the blocker that must be cleared before
the no-encap default can move.

**Dual ToR.**  In the dual-ToR topology, no-encap pod-to-pod routes inherit
their "dual-ness" from the node-to-node routes that BGP computes, so BIRD must
keep programming them.  This is a reason the no-encap default cannot simply
follow IPIP's; if it does move, dual-ToR clusters will need either documentation
telling them to pin the old value, or an `Auto` value that detects the topology.

**External BGP infrastructure.**  Clusters where an external BGP fabric already
programs the cluster routes (a common OpenStack deployment shape) may need
`FelixConfiguration.programClusterRoutes: Disabled` to keep Felix out of the
way.  This is a documentation and release-note obligation, not a code one.

### Review notes — §5

- Closing any of these gaps means editing this section, not appending a new
  one.  A gap list that only grows stops being read.

## 6. Keep this doc in sync with the code

A PR that changes which component programs cluster routes, the enum values or
defaults of either `programClusterRoutes` field, the BIRD kernel-programming
filter, or the deprecation and removal plan, must update this file in the same
PR.  Exemptions: a bug fix restoring behaviour this doc already describes, a
mechanical refactor with no observable change, comment or log-message edits, and
dependency bumps.  If in doubt, update.

Related designs:

- [`felix/design/dataplane.md`](../../felix/design/dataplane.md) — the manager
  and route-table architecture that `ipipManager` and `noEncapManager` sit in.
- [`felix/design/calc-graph.md`](../../felix/design/calc-graph.md) —
  `L3RouteResolver` and `EncapsulationResolver`.
- [`node/DESIGN.md`](../../node/DESIGN.md) — the node container that runs Felix,
  confd and BIRD side by side.
