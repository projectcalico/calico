# WS-G: tigera/operator integration

At the scales hierarchical Typha targets, Calico is deployed by the
tigera/operator, which owns the typha Deployment, RBAC, Services, certs, and —
critically — a typha **autoscaler**. The chart/manifest changes in WS-B/C/E
cover the OSS-manifest path; this workstream makes the operator able to deploy
and manage hierarchical typha. Work happens in the **tigera/operator repo**
(local worktree: `/home/shaun/go-os/src/github.com/tigera/typha-multi`).

All file:line refs below are into that worktree (verified at planning time).

## Required reading

- `plans/hierarchical-typha/00-overview.md`, `02-…`, `03-…`, `05-…` (the
  calico-repo features being deployed)
- operator `pkg/render/typha.go` — whole file: ServiceAccount `calico-typha`
  (172-180), ClusterRole (206-387), Deployment (389-499), env (603-663),
  probes (711-734), Service (736-769), PDB (148-165), anti-affinity (789-808)
- `pkg/controller/utils/component.go:1017-1098` —
  `setStandardSelectorAndLabels` (how pod labels/selectors get applied)
- `pkg/common/autoscale.go:32-56` + 
  `pkg/controller/installation/typha_autoscaler.go:199-251` — replica formula
  (`nodes/200 + 2`, min 3 above 4 nodes) and sync loop
- `pkg/controller/installation/core_controller.go:1856-1891` — TLS keypairs:
  `typha-certs` (CN `typha-server`, server-auth usage), `node-certs`
  (CN `typha-client`, client-auth usage)
- `pkg/render/node.go:1478-1482` — felix told `FELIX_TYPHAK8SSERVICENAME=
  calico-typha`, `FELIX_TYPHAK8SNAMESPACE=calico-system` (hardcoded)
- `api/v1/installation_types.go` + `api/v1/typha_deployment_types.go` —
  customization surface (TyphaDeployment overrides: env, pod labels,
  resources, affinity… but NOT SA name, services, RBAC)

## What needs operator changes (by calico-repo workstream)

### For WS-B (leader election) — required before hierarchy can be enabled at all

1. **RBAC** (ClusterRole `calico-typha`, `pkg/render/typha.go:206-387` — note
   typha has its **own SA**, unlike the OSS manifests which use calico-node;
   the calico-repo chart RBAC edits in WS-B target a different role than this
   one):
   - `coordination.k8s.io` `leases`: `get, create, update` (+ `watch, list`
     for WS-E lazy candidacy).
2. **Downward API env** on the typha container (env list at 603-663 has no
   fieldRefs today): `TYPHA_PODNAME` (metadata.name), `TYPHA_PODNAMESPACE`
   (metadata.namespace — don't hardcode `calico-system`; the render already
   sets `TYPHA_K8SNAMESPACE` from the render namespace, keep consistent),
   `TYPHA_NODENAME` (spec.nodeName).
3. **Election env**: `TYPHA_LEADERELECTIONENABLED`, lease name/namespace and
   timing params — only where they differ from typha defaults.

### For WS-C (promotion/demotion, single-tier) — the M2 deployment

4. **RBAC**: `pods` `patch` (self-labelling). The operator does **not**
   reconcile labels on running pods (only the pod template via
   `setStandardSelectorAndLabels`), so typha patching its own tier/role label
   sticks — confirmed no fight.
5. **Pod template label**: add `projectcalico.org/typha-tier: "2"` to the
   typha PodTemplateSpec (render currently sets only annotations at 451-454;
   labels come from `setStandardSelectorAndLabels` — add the tier label in the
   render, and make sure it is NOT part of the Deployment selector, which is
   pinned to `k8s-app: calico-typha` and must stay immutable).
6. **Leader Service**: render `calico-typha-leader` (selector
   `projectcalico.org/typha-role: leader`, same port 5473) alongside the
   existing Service (736-769). Don't touch `calico-typha`'s selector — per
   the client-side leader policy (below) it keeps selecting all typhas.
7. **Hierarchy enable plumbing**: env `TYPHA_HIERARCHYENABLED=true` plus the
   upstream-discovery params pointing at the leader Service.
8. **TLS for typha-as-client**: typha's server cert (`typha-certs`,
   CN `typha-server`) has server-auth usage only; typha connecting out needs a
   **client** cert that satisfies the upstream's `TYPHA_CLIENTCN=typha-client`
   check (set at typha.go:~640 from `NodeCommonName`). Issue a new keypair
   `typha-client-certs` with CN `typha-client` + client-auth usage
   (core_controller.go:1856-1891 pattern), mount into typha, and set
   `TYPHA_CLIENTCERTFILE/CLIENTKEYFILE/CLIENTCAFILE` +
   `TYPHA_UPSTREAMSERVERCN=typha-server`. Do **not** reuse the `node-certs`
   secret object (same CN is fine; sharing the private key across components
   is not). Certificate-management variants (BYO certs, certificate
   management enabled) must be handled the same way `node-certs` is.
9. **Probes**: unchanged — follower readiness semantics come from typha
   itself (snapcache in-sync), already surfaced on the same `/readiness`.

### For WS-E (two-tier)

10. **Tier-1 Service**: render `calico-typha-tier1` (selector tier label
    `"1"`).
11. **Installation API**: new optional field, e.g.
    `Installation.Spec.TyphaHierarchy { Enabled bool; Tier1Count *int32 }`
    (exact shape per operator API conventions; TyphaDeployment overrides can
    technically inject env vars already, so early testing needs no API change,
    but the real feature deserves a first-class field + validation +
    docs). Operator API changes need the usual CRD regen.
12. **Autoscaler interaction** (`typha_autoscaler.go`): formula stays
    node-count based but must now produce **total** replicas =
    client-serving tier-2 need (`nodes/200`-ish) + `1` leader + `Tier1Count`,
    and the min-3-for-HA floor needs rethinking in hierarchy mode (leader +
    tier-1 are not client-serving capacity). Keep the change minimal:
    `replicas = legacyFormula(nodes) + 1 + tier1Count` when hierarchy enabled.
13. **Felix-side discovery config** (`pkg/render/node.go:1478-1482`): if WS-E
    adds Felix config for the multi-service/tier-aware discovery (open
    question in WS-E), plumb the env here; otherwise nothing — Felix keeps
    `FELIX_TYPHAK8SSERVICENAME=calico-typha` and learns tier info from the
    extra services automatically.

### Non-issues (checked, no operator change)

- PDB (`calico-typha`, maxUnavailable 1) — fine as-is; revisit only if leader
  failover during disruption proves too slow in soak.
- Anti-affinity, priority class, hostNetwork, rolling-update strategy — all
  compatible.
- WS-A and WS-D are pure typha-internal/protocol features — no operator
  surface beyond the env plumbing above.

## Sequencing

Operator PRs trail the calico-repo milestones: one operator PR for items 1-3
(+8, since TLS is a prerequisite to typha dialling out) targeting M2, gated on
the new `TyphaHierarchy.Enabled` (or, pre-API, on an annotation/env override
for dev); a second PR for items 10-13 targeting M3. Use the
`operator-versioning` mapping to pick the right operator branch for the calico
release the feature lands in; calico-repo PRs that need these get the
`needs-operator-pr` label.

Dev/test loop before operator support lands: deploy with the operator, then
use the `unsupported.operator.tigera.io/ignore=true` bypass annotation (see
the `replace-tigera-component` workflow) or TyphaDeployment env overrides to
hand-wire hierarchy mode on a test cluster.

## Test matrix

- Operator UT: render tests for RBAC/env/services/labels/cert (operator repo
  has comprehensive render UT patterns next to `typha.go` — follow them);
  autoscaler UT for the hierarchy formula.
- Operator FV: the operator repo's envtest-based controller tests for the new
  Installation field defaulting/validation.
- End-to-end: kind/GCP cluster, operator-deployed, hierarchy on: leader kill,
  scale node count past an autoscaler boundary, rolling upgrade of typha
  Deployment. (Coordinates with WS-F's gates.)

## Acceptance criteria

- `TyphaHierarchy.Enabled=false` (or field absent): rendered objects
  byte-identical to today (render UT golden-diff).
- Enabled on an operator-managed cluster: typhas self-organise with zero
  manual steps; certs, RBAC, services all reconciled by the operator;
  autoscaler keeps tier-2 capacity ≈ legacy capacity.
