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

| FelixConfiguration   | BGPConfiguration     | Result                                                                                             |
|----------------------|----------------------|----------------------------------------------------------------------------------------------------|
| `EnabledIPIPOnly`    | `EnabledNoEncapOnly` | **The default from v3.33.** Felix owns IPIP, BIRD owns no-encap.                                   |
| `Enabled`            | `Disabled`           | Felix owns everything; BIRD programs no cluster routes.                                            |
| `Disabled`           | `Enabled`            | The pre-v3.33 default.  BIRD owns everything.  Deprecated in v3.33 when IPIP pools are configured. |
| `EnabledNoEncapOnly` | `EnabledIPIPOnly`    | Felix owns no-encap, BIRD owns IPIP.  Deprecated in v3.33.                                         |

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

| Location                                 | Role                                                                                                                                                                                                                                                              |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `felix/config/config_params.go`          | `ProgramClusterRoutes` param (`oneof`, default `EnabledIPIPOnly`) and the `ProgramIPIPClusterRoutes()` / `ProgramNoEncapClusterRoutes()` accessors.  Nothing outside config should compare the raw string.                                                        |
| `felix/calc/encapsulation_resolver.go`   | `NoEncapNeeded()` incorporates `ProgramNoEncapClusterRoutes()`: it means "there are unencapsulated pools *and* Felix owns their cluster routes".  `IPIPEnabled()` does **not** fold ownership in, because the IPIP tunnel device is Felix's to manage either way. |
| `felix/calc/calc_graph.go`               | Gates construction of the `L3RouteResolver` on there being some encapsulation whose routes Felix owns.                                                                                                                                                            |
| `felix/dataplane/driver.go`              | Copies the two booleans into the dataplane `Config`.                                                                                                                                                                                                              |
| `felix/dataplane/linux/int_dataplane.go` | `ProgramIPIPClusterRoutes` / `ProgramNoEncapClusterRoutes`; the no-encap managers are only created when Felix owns no-encap.                                                                                                                                      |
| `felix/dataplane/linux/ipip_mgr.go`      | The IPIP manager always runs (it owns `tunl0`), but only feeds its route manager when Felix owns IPIP cluster routes.                                                                                                                                             |

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

The kernel-programming filter is not the only one that varies with ownership.
`calico_export_to_bgp_peers` varies too: BIRD's kernel protocol runs with
`learn`, so once Felix owns the IPIP cluster routes BIRD picks them up as its
own, and a kernel-learned route is not subject to the iBGP
no-re-advertisement rule.  `processIPPools` therefore adds `tunl0` to the
tunnel-route reject (`IBGPExportFilterForTunnelRoutes`) exactly when Felix is
the owner.  The `*.cali` / `*.calico` arms of that reject are unconditional,
because Felix always owns VXLAN and WireGuard routes.

What does *not* vary is the rest of the export path: whether this node should
advertise a prefix it owns is a separate question from who writes the route to
this node's kernel.  `TestFelixClusterRoutesNotReadvertised`
(`node/tests/k8st/tests/cluster_routes_test.go`) is what holds the `tunl0` arm
in place — it asserts that no node exports another node's block once Felix is
programming the route to it.

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
- `NoEncapNeeded` conflating "pools exist" with "Felix owns them" is a trap
  for new code.  If you need "unencapsulated pools exist" irrespective of
  ownership, add a separate accessor rather than un-conflating this one — the
  encap summary is compared field-by-field to decide whether Felix must restart
  (`encapsulation_resolver.go`), and changing what a field means changes when
  Felix restarts.
- confd renders both the IPv4 and IPv6 templates from the same policy.  IPIP is
  IPv4-only in practice, but `processIPPool` must not assume that: it keys off
  the pool's `ipipMode`, not the IP version.
- Any test that disables BGP and then expects cross-node connectivity to break
  is implicitly asserting that BIRD owns the routes.  Felix derives its routes
  from the datastore, so they outlive the BGP session and the assertion fails.
  Such a lane must pin the mode — in CI, via the
  `hack/test/kind/infra/values-bird-routing.yaml` overlay — rather than rely on
  the default, which no longer means BIRD for IPIP.  The `bgp` e2e suite guards
  this itself in `requireBGPIsSoleRoutingMechanism`.

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

A cluster moves between BIRD-programmed and Felix-programmed IPIP cluster routes
in one of two ways, and only one of them has a gap.

**Upgrading the code.**  On upgrade to v3.33, a cluster with IPIP pools and no
explicit configuration changes owner without anything in the datastore changing:
both `programClusterRoutes` fields are unset before and after, and what moves is
the *default* each component derives from unset.  The calico-node pod is
replaced, so:

1. The old BIRD exits.  Its kernel protocol is configured with `persist`, so it
   deliberately leaves its routes in the kernel instead of withdrawing them.
2. The new pod's confd renders `bird_ipam.cfg` so that
   `calico_kernel_programming` rejects the IPIP pools' CIDRs, and Felix starts
   programming those CIDRs with its own route protocol (`DeviceRouteProtocol`,
   default 80).
3. If BGP is still enabled, the new BIRD starts with `-R`, holds the routes it
   found through its graceful-restart recovery period, and then reconciles.  By
   then Felix has taken over the destinations it wants, so to BIRD those are
   alien routes that it learns rather than removes; what is left to reconcile is
   whatever Felix did not want.

There is no window in which a destination Felix wants has no route: Felix
programs with `RouteReplace` (`felix/routetable/route_table.go`), which
atomically replaces any previous route for the same prefix whether or not it was
within Felix's logical ownership.

**Changing the configuration on a running cluster.**  Setting either
`programClusterRoutes` field explicitly is picked up live: confd re-renders and
BIRD reconfigures in place.  That BIRD knows it exported those routes, so it
withdraws them itself.  Felix restarts on the config change and starts
programming the same CIDRs.

This is the path with the gap: BIRD withdraws promptly, while Felix *restarts*
because its configuration changed and only programs the destinations once it is
back.  The gap is the length of a Felix restart, and it is unmeasured.  A cluster
that cannot tolerate any cross-node packet loss should prefer the upgrade path,
or make the change during a maintenance window.

Once Felix has re-programmed a destination, BIRD cannot withdraw it out from
under Felix: a delete carrying `RTPROT_BIRD` does not match a route that is now
Felix's proto 80, since the kernel matches on protocol when the delete specifies
one.

**Where BIRD does not come back.**  Step 3 is what removes BIRD's persisted
routes in the ordinary upgrade, and it does not happen if BGP is disabled as
part of the same migration, if BIRD is not run because the cluster has no BGP
peers, or if BIRD never completes recovery.  Nothing else would remove them:
they are not Felix's by protocol, and BIRD is not there to reconcile them.  So
Felix's route-ownership policy claims routes via the IPIP device that carry
BIRD's protocol, whenever Felix is the configured owner of the IPIP cluster
routes (`OwnBIRDIPIPRoutes`, `felix/routetable/ownershippol`), so that
reconciliation removes them.

The rule matters only for destinations Felix does **not** want — a block
released while the node was down, a node that has left the cluster, a deleted
pool.  Destinations it does want are covered by the atomic replace above; these
have no desired route to overwrite them, so without the rule and without a BIRD
to reconcile them they would stay in the kernel indefinitely.

### Review notes — §4

- Any change to the handover must keep the property that *both* components
  reach the same conclusion from the same datastore state.  The only reason the
  window is short is that confd and Felix are reacting to the same change at the
  same time; introducing a staged or operator-driven migration would need the
  intermediate state to be explicitly representable in the API, not implied.
- The ownership rule is deliberately not time-bounded, and not conditional on
  having recently upgraded.  Felix has no notion of "we just upgraded", and a
  bounded window would fail precisely the cases the rule exists for: a node down
  across the window, a rolling upgrade slower than it, or BGP being switched off
  weeks after the version moved.
- Do not widen the rule to every protocol on `tunl0`.  Felix's own routes there
  are already claimed by protocol, whoever the configured owner is, so widening
  it would only take in routes belonging to neither Felix nor BIRD.  It is also
  deliberately not scoped by destination; see the field comment for why.

## 5. Known gaps

These are recorded so that a future change does not mistake them for solved
problems.

**Felix-programmed no-encap cluster routes and BGP re-advertisement.**  BIRD's
kernel protocol is configured with `learn`, so it learns alien kernel routes —
including the cluster routes Felix programs.  `calico_export_to_bgp_peers`
rejects the ones that leave via a Calico tunnel device: `*.cali` / `*.calico`
(VXLAN, WireGuard) and, since the IPIP default moved, `tunl0`.  Felix-programmed
*no-encap* routes leave via an ordinary NIC, so they are still not caught, and a
node can end up advertising other nodes' blocks to its iBGP peers.  Whether that
actually misadvertises anything for no-encap is not established; it is tracked,
with the history of this filter, in CORE-13346.

The scope of the reject is deliberate on one axis and a proxy on the other:

- **External peers are out of scope by decision, not by omission.**  The reject
  is applied only to internal peers, so a node does go on advertising these
  routes to its eBGP peers.  That is intended: some deployments peer to their
  external BGP infrastructure from only a *subset* of cluster nodes, so an
  external peer may never hear from the node that programs a workload's local
  route, and has to learn that workload's block from another node's remote
  route instead.  Suppressing the advertisement would break those deployments.
  An operator who does want it suppressed can express that with a BGPFilter
  `interface` rule, which is what that field exists for.  Any remaining work
  here is therefore about the iBGP case only.
- Matching on interface name is a proxy for the property we actually want, which
  is "a route this node owns" versus "a route this node learned or synthesised".
  A route protocol test (`krt_source` against Felix's `DeviceRouteProtocol`)
  combined with "has a next hop" would express that directly and cover every
  encapsulation at once; doing it in the kernel protocol's *import* filter would
  keep the routes out of BIRD's table entirely.  Note that BIRD learning Felix's
  *local* workload routes is load-bearing — `calico_aggr()` reads their
  `krt_metric` to advertise the elevated-priority /32 during live migration — so
  any such filter must exclude only the remote ones.

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

## 6. Related designs

- [`felix/design/dataplane.md`](../../felix/design/dataplane.md) — the manager
  and route-table architecture that `ipipManager` and `noEncapManager` sit in.
- [`felix/design/calc-graph.md`](../../felix/design/calc-graph.md) —
  `L3RouteResolver` and `EncapsulationResolver`.
- [`node/DESIGN.md`](../../node/DESIGN.md) — the node container that runs Felix,
  confd and BIRD side by side.
