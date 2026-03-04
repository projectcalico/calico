# Removing the Calico API Server

|  |  |
| :---- | :---- |
| **PMREQ** | N/A \- engineering-driven initiative |
| **EPIC** | [CORE-11861](https://tigera.atlassian.net/browse/CORE-11861) / [calico\#6412](https://github.com/projectcalico/calico/issues/6412) |
| **Author(s)** | @caseydavenport |
| **Timeline** | v3.32.0 (tech preview), future releases for full migration |
| **Open source?** | OSS \+ Enterprise |
| **Release target** | Calico v3.32.0 (initial), ongoing |

## Open questions

- Migration tooling for existing clusters (v1 CRDs \-\> v3 CRDs) not yet implemented. How automated should this be?  
- Authorization webhook for audit logging \+ GET/LIST/WATCH tier RBAC not yet designed. Needs k8s API server changes, which isn't available on managed platforms.  
- When do we formally deprecate the API server? Need to build confidence with tech preview first.  
- How do we handle Calico Cloud implications (UI tier naming assumptions, etc.)?

## Background

Calico has historically used an [aggregation API server](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/) to serve `projectcalico.org/v3` APIs. It stores validated \+ defaulted resources as CRDs in the `crd.projectcalico.org/v1` API group. Some early groundwork for handling the two-API-group coexistence was done in [calico\#8586](https://github.com/projectcalico/calico/pull/8586), which ensured distinct UIDs for `projectcalico.org/v3` resources vs their `crd.projectcalico.org/v1` backing storage.

This two-API-group model exists for a few reasons:

- When it was created, CRDs were not GA nor as feature-rich as they are today.  
- Complex cross-field/cross-object validation (e.g., IP pool overlap checks) couldn't be expressed in OpenAPI schemas.  
- It provided a unified experience for both etcd and KDD modes.

However, times have changed. CRDs, webhooks, and CEL validation have matured significantly. The API server has become a constant source of friction:

- **User confusion**: Two API groups that look almost identical but have subtle differences. This is a VERY common source of user issues \- see [\#6412](https://github.com/projectcalico/calico/issues/6412) (20+ reactions, 19 comments).  
- **Ordering dependencies**: The API server needs Calico networking to run, but `projectcalico.org/v3` isn't usable until it's up. This can be tricky for GitOps tools like Flux and ArgoCD.  
- **Platform friction**: `hostNetwork` bugs on EKS, AKS. Managed platforms that host control planes outside the cluster (looking at you, EKS) make aggregate API servers particularly painful.  
- **Code burden**: \~3k LOC per new API. Massive k8s library imports. The API server has been the root cause of dozens of CIs, GH issues, and bugs over the years.  
- **HA complexity**: Must be running, healthy, and HA before APIs are accessible.

## Requirements

1. Calico components can optionally use `projectcalico.org/v3` APIs backed directly by CRDs instead of the aggregation API server.  
2. Validation, defaulting, and RBAC currently provided by the API server must be replicated via CRD validation, webhooks, and controllers.  
3. Existing clusters must be able to migrate from the old model to the new one.  
4. The API server continues to work for clusters that haven't migrated yet.  
5. Policy tier naming restrictions (`<tier>.<name>` prefix) should be removed as part of this work.  
6. All of this should land as tech preview in v3.32.0.

## Specification

### Limitations / out-of-scope

- **Full migration tooling**: Automated v1 \-\> v3 CRD data migration is not yet implemented. This will come in a follow-on release.  
- **Authorization webhook**: Tier-based RBAC for GET/LIST/WATCH requires a Kubernetes authorization webhook, which needs k8s API server configuration changes. Not available on all platforms.  
- **Audit logging**: The authorization decision is not currently included in audit logs (admission webhooks don't have this capability).  
- **LicenseKey enforcement**: Not present in the webhook path. This was bypassable anyway via `crd.projectcalico.org` directly, so this is probably fine.  
- **etcd mode**: This work doesn't apply to etcd mode.

### High-level user stories

- Cluster admins can install Calico without a dedicated API server and still use `projectcalico.org/v3` APIs directly via CRDs.  
- Cluster admins can use `kubectl apply -f` with `apiVersion: projectcalico.org/v3` resources without needing an API server pod running first.  
- GitOps tools (Flux, ArgoCD, etc.) can manage Calico resources without ordering dependency headaches.  
- Policy authors can name their policies whatever they want, without being forced to prefix with `<tier>.`.  
- Cloud platforms bundling Calico have a simpler integration story.

### Behavioral changes

#### The toggle

An environment variable `CALICO_API_GROUP` controls which API group the KDD backend uses. Components auto-detect which API group to use based on the Kubernetes discovery API:

- If `CALICO_API_GROUP` is explicitly set, use that value.  
- If `projectcalico.org/v3` CRDs exist AND `crd.projectcalico.org/v1` does NOT, use v3.  
- If both exist, use v1 (the API server is providing v3 via aggregation).  
- Default to v1 if discovery fails.

This lives in `libcalico-go/lib/backend/k8s/discovery.go`.

#### Policy name changes

The `<tier>.<name>` prefix requirement for policies in non-default tiers has been removed. Policies are now identified entirely by `(kind, namespace, name)`. The tier is a field on the policy, not part of its identity.

A migration controller in kube-controllers automatically renames existing default-tier policies from their `default.<name>` storage format to just `<name>`.

### API changes

#### New CRDs

22 new CRD definitions in the `projectcalico.org/v3` API group, covering all existing resource types:

- NetworkPolicy, GlobalNetworkPolicy, StagedNetworkPolicy, StagedGlobalNetworkPolicy, StagedKubernetesNetworkPolicy  
- IPPool, IPReservation, IPAMConfiguration, IPAMHandle, IPAMBlock, BlockAffinity  
- BGPConfiguration, BGPFilter, BGPPeer  
- HostEndpoint, Profile, Tier, NetworkSet, GlobalNetworkSet  
- FelixConfiguration, KubeControllersConfiguration, ClusterInformation, CalicoNodeStatus

Generated CRD YAMLs are in `api/config/crd/` and `manifests/v3_projectcalico_org.yaml`.

#### IPPool status conditions

A new `Conditions` array on IPPool status allows controllers to mark pools as disabled. This replaces the synchronous cross-object validation that the API server used to do for overlapping CIDRs. IPAM code checks for a `` `Allocatable` `` condition before allocating IPs from a pool.

#### model.PolicyKey changes

The internal `model.PolicyKey` now includes `Kind` and `Namespace` fields in addition to `Name`. The `Name` field is now the proper user-facing API name (no tier prefix), and `Tier` has been removed from the key.

## Technical Design

### Architecture overview

The implementation touches four main areas:

1. **CRD generation \+ libcalico-go dual-mode support** ([calico\#10447](https://github.com/projectcalico/calico/pull/10447))  
2. **Policy name tier prefix removal** ([calico\#11232](https://github.com/projectcalico/calico/pull/11232))  
3. **Webhook-based validation and RBAC** ([calico\#11803](https://github.com/projectcalico/calico/pull/11803))  
4. **Operator support** ([operator\#4092](https://github.com/tigera/operator/pull/4092))

**New flow (v3 CRD mode):**

- kubectl / API client writes to `projectcalico.org/v3` CRDs directly  
- Validation/RBAC webhooks intercept mutations (limited to just a handful of resource types)  
- libcalico-go reads/writes `projectcalico.org/v3` CRDs (auto-detected)  
- Felix / Typha / etc. consume resources via libcalico-go

**Old flow (API server mode):**

- kubectl / API client writes to `projectcalico.org/v3` via the aggregation API server  
- API server validates, defaults, and stores as `crd.projectcalico.org/v1` CRDs  
- libcalico-go reads/writes `crd.projectcalico.org/v1` CRDs  
- Felix / Typha / etc. consume resources via libcalico-go

### 1\. CRD generation and dual-mode support

**PR**: [calico\#10447](https://github.com/projectcalico/calico/pull/10447) (merged Feb 2, 2026 \- 54k additions, 287 files)

This was the foundational PR. Key decisions:

- **CRD definitions live in `api/pkg/apis/projectcalico/v3/`** alongside the existing v3 types. The CRD structs *are* the API types \- no translation layer.  
- **libcalico-go has a runtime toggle** to select which API group to use. All resource clients check `BackendAPIGroup()` to determine which REST client to instantiate.  
- **Translation logic is skipped in v3 mode.** The old v1 backend performed UUID reversal, metadata annotation manipulation, and name prefixing. None of this is needed when storing directly as v3 CRDs.  
- **Short names** are defined natively in the CRD specs.  
- **New IPAM CRDs**: `IPAMHandle`, `IPAMBlock`, and `BlockAffinity` now exist as v3 CRDs. Previously these were only `crd.projectcalico.org/v1` internal resources.

### 2\. Policy name tier prefix removal

**PR**: [calico\#11232](https://github.com/projectcalico/calico/pull/11232) (merged Dec 4, 2025 \- net \-12.3k lines across 244 files)

This was a prerequisite for CRD mode. With CRDs, we can't intercept API requests to add/remove tier prefixes, so the naming must be clean from the start.

**What changed:**

- Removed validation requiring `<tier>.` prefix on non-default-tier policies.  
- Tier is now purely a field on the policy, not part of its identity.  
- `model.PolicyKey` augmented with `Kind`, `Namespace` fields.  
- Felix dataplane protobuf updated to carry full policy identity.  
- Flow log API updated accordingly.

**Migration controller** (`kube-controllers/pkg/controllers/networkpolicy/policy_name_migrator.go`):

- Runs in kube-controllers, enabled by default.  
- Identifies default-tier policies where the v1 datastore name (`default.<name>`) differs from the v3 name (`<name>`).  
- Creates the policy with the correct name, deletes the old one.  
- Waits for calico-node rollout before starting.  
- Reconciles every 5 minutes.  
- Can be disabled via `KubeControllersConfiguration` if needed.

### 3\. Webhooks

Two webhook mechanisms replace API server logic:

#### Tier-based RBAC webhook

**PR**: [calico\#11803](https://github.com/projectcalico/calico/pull/11803) (merged Feb 18, 2026\)

A validating admission webhook in `webhooks/pkg/rbac/rbac.go` that:

- Intercepts CREATE/UPDATE/DELETE on all policy types.  
- Checks if the user has GET access to the relevant Tier resource.  
- Checks if the user has the appropriate verb on `tier.<resource>`.  
- Integrates with the Kubernetes authorization API (SubjectAccessReview).

**Known limitation**: This only covers CRUD operations, not GET/LIST/WATCH. Admission webhooks are not invoked for read operations. Fixing this would require a proper Kubernetes authorization webhook, which requires API server configuration changes not available on managed platforms.

#### CEL-based mutation policy

Defined in `api/admission/networkpolicy.mutatingadmissionpolicy.yaml`:

- Uses Kubernetes 1.29+ MutatingAdmissionPolicy (CEL-based).  
- Automatically defaults the `types` / `policyTypes` field on policy resources.  
- Handles ingress-only, egress-only, and both based on which rules are present.

### 4\. IPPool cross-object validation

**PR**: [calico\#11775](https://github.com/projectcalico/calico/pull/11775) (merged Feb 10, 2026\)

The API server used to synchronously validate that IP pool CIDRs don't overlap with existing pools. Without it, we need an alternative. There were three options considered:

* Handle the overlaps on read from the IPAM code, using a tie breaker.  
* Use an Admission Webhook to perform the validation.  
* Asynchronous detection, and reporting of conflicts using status.

Ultimately, we settled on an an async approach in order to provide good feedback without the need for a webhook:

- A new `Conditions` field on IPPool status.  
- A controller sets a `Disabled` condition on pools that fail validation.  
- IPAM code checks for this condition and won't allocate from disabled pools.

This is a fundamental shift from synchronous reject-at-write to asynchronous detect-and-disable. It's not as strict, but it's pragmatic \- the API server validation was already bypassable via `crd.projectcalico.org` anyway.

### 5\. Operator changes

**PRs**: [operator\#4092](https://github.com/tigera/operator/pull/4092) (merged Feb 3, 2026), plus follow-ups [operator\#4401](https://github.com/tigera/operator/pull/4401), [operator\#4417](https://github.com/tigera/operator/pull/4417), [operator\#4419](https://github.com/tigera/operator/pull/4419), [operator\#4428](https://github.com/tigera/operator/pull/4428)

#### API group detection

At startup, the operator determines which API group to use via `apis.UseV3CRDS()` in `pkg/apis/version.go`. The logic mirrors libcalico-go's detection:

- If `CALICO_API_GROUP` env var is set, use that value directly.  
- Otherwise, query the Kubernetes discovery API. Use v3 CRDs only if `projectcalico.org` is present AND `crd.projectcalico.org` is NOT.

The result is stored in `options.AddOptions.UseV3CRDs` and threaded to all controllers.

#### CRD bundles

The operator embeds two parallel sets of Calico CRD YAML files:

- `pkg/crds/calico/v1.crd.projectcalico.org/` \-- traditional CRDs  
- `pkg/crds/calico/v3.projectcalico.org/` \-- new v3 CRDs

The `GetCRDs()` function selects which set to load based on the `UseV3CRDs` flag. Enterprise CRDs follow the same pattern under `pkg/crds/enterprise/`.

#### API server deployment: OSS vs Enterprise

The `APIServer` CR (`operator.tigera.io/v1`) is what triggers the operator's `apiserver-controller` to deploy the API server. The behavior in v3 CRD mode differs. 

Namely, it will install the necessary Webhooks, but will not install the aggregation API server itself.  

When the aggregation server is not needed, the operator also cleans up aggregation-specific resources:

- `APIService` registrations (`v3.projectcalico.org`, etc.)  
- Auth-related ClusterRoles/ClusterRoleBindings (`calico-apiserver-auth`, `calico-policy-passthru`)  
- Audit policy ConfigMap and audit log volumes  
- Enterprise-specific passthrough RBAC (`calico-uisettings-passthru`, `uisettingsgroup-getter`)

#### 

#### Other operator changes

- **Forked CRD structs removed**: The entire `pkg/apis/crd.projectcalico.org/v1/` directory was deleted. The operator now imports all types from the Calico API package directly and dynamically registers them in the correct API group.  
- **Scheme registration**: `pkg/apis/register.go` conditionally registers Go types in either `projectcalico.org/v3` or `crd.projectcalico.org/v1` based on the mode. Some types (like policy types, Tier) are always in v3; others (BGPConfiguration, FelixConfiguration, IPPool, etc.) vary.  
- **CNI plugin config**: The node render passes `calico_api_group` in the CNI JSON config so the CNI plugin knows which API group to use.  
- **RBAC broadened**: All ClusterRole rules were updated to include both API groups (`projectcalico.org` and `crd.projectcalico.org`) so RBAC works regardless of mode.  
- **Controller wait logic**: Many controllers (gatewayapi, applicationlayer, egressgateway, etc.) were updated to skip waiting for the API server to be ready when `UseV3CRDs` is true.  
- **Helm chart**: No longer bundles `crd.projectcalico.org` CRDs inline \- they must be created/updated before running the chart. These are now in a separate chart, and a new equivalent chart also exists for the v3 CRDs.  
- The operator does not yet import or deploy the CEL MutatingAdmissionPolicy YAMLs from the Calico repo ([CORE-12315](https://tigera.atlassian.net/browse/CORE-12315)). These need to be deployed for policy `types` defaulting to work in v3 CRD mode.

### 6\. Manifest install support

For users who install Calico via raw manifests (i.e., without the operator), the webhooks and admission policies need to be included in the manifest install path. This includes the RBAC webhook deployment, its TLS certificate setup, and the CEL MutatingAdmissionPolicy YAMLs. Currently, these are only wired up via the operator. Manifest-based installs need their own integration ([CORE-12362](https://tigera.atlassian.net/browse/CORE-12362)).

### 7\. Enterprise considerations

**PR**: [calico-private\#10775](https://github.com/tigera/calico-private/pull/10775) (merged Feb 13, 2026\)

Cherry-pick of the CI/test changes with enterprise-specific additions:

- New kube-controllers `LicenseKey status` controller to update LicenseKey status that was previously handled by the API server.

Areas still in progress for enterprise:

- Calico Cloud UI may have tier naming assumptions that need updating.  
- [AuthorizationReview API moved to ui-apis](https://docs.google.com/document/d/14LmfkbVpa8BTVE4fkNh_zjoLI1Ipr1Y1BwaitZ4d0j0/edit?tab=t.0#heading=h.undpsheiba4h)

### CI and Testing

**PR**: [calico\#11758](https://github.com/projectcalico/calico/pull/11758) (merged Feb 5, 2026\)

- New CI job subsets that run against `projectcalico.org/v3` CRDs.  
- libcalico-go tests run against both v1 and v3 API groups.  
- node k8st tests run against v3 CRDs.  
- Tests use `CALICO_API_GROUP` env var to select mode.

This is the beginning \- eventually v3 CRD mode will be the default in CI.

## General considerations

### Open-source / enterprise

All core changes are in open-source Calico. Enterprise-specific changes are limited to:

- LicenseKey status controller (calico-private).  
- [AuthorizationReview API  (in ui-apis)](https://docs.google.com/document/d/14LmfkbVpa8BTVE4fkNh_zjoLI1Ipr1Y1BwaitZ4d0j0/edit?tab=t.0#heading=h.undpsheiba4h)  
- Any Calico Cloud UI updates for tier naming.

The refactoring was done in OSS first to avoid merge conflicts.

### Upgrade/Downgrade

**From v3.31 \-\> v3.32:**

- The policy name migration controller runs automatically on upgrade.  
- Existing clusters continue to use the API server by default (auto-detection sees both API groups and picks v1).  
- To opt in to v3 CRD mode, set `CALICO_API_GROUP=projectcalico.org/v3`.

**Downgrade considerations:**

- Policies renamed by the migration controller (removing `default.` prefix) should continue to work since the old code also understands unprefixed names for default-tier policies.  
- If a cluster was switched to v3 CRD mode, downgrading requires switching back to v1 mode and ensuring the API server is running.

### Version skew

The `CALICO_API_GROUP` env var must be consistent across all components. The operator handles this when managing the installation. For manifest-based installs, the user is responsible.

The policy name migration controller should complete before any component restarts rely on the new naming convention. It waits for calico-node rollout to ensure Felix has the new protobuf format.

### Scale

No significant scale impact expected. CRDs are served by the kube-apiserver, which already handles our v1 CRDs at scale. Removing the aggregation layer actually reduces load since requests no longer proxy through an additional server.

The webhook adds latency to policy CRUD operations, but this is comparable to what the API server was already doing (and it is limited to the resources that need the webhook).

### Troubleshooting

- Check `CALICO_API_GROUP` env var across all components for consistency.  
- Check kube-controllers logs for policy name migration status.  
- Check webhook pod logs for RBAC and validation issues.  
- The auto-detection logic logs which API group it selected at startup.

### Diagnostics

The `calico-node` diags bundle currently collects `crd.projectcalico.org/v1` CRD data. It needs to be updated to also collect `projectcalico.org/v3` CRDs when running in v3 CRD mode ([CORE-12359](https://tigera.atlassian.net/browse/CORE-12359)). Without this, support bundles from v3-mode clusters would be missing Calico resource data.

### Security

- The RBAC webhook uses TLS (port 6443).  
- Tier-based RBAC is enforced via SubjectAccessReview, the same authorization mechanism as before.  
- The main security gap is GET/LIST/WATCH not being covered by admission webhooks. This is documented as a known limitation.