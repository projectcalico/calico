<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Webhooks — Design

`calico component webhook` is one process serving several HTTP endpoints on a single TLS listener. Two of them enforce Calico's tier-based RBAC on tiered policy resources; one protects `ClusterInformation` from being written by anything other than Calico's own components.

Install steps, break-glass, and cert rotation live in [`webhooks/config/README.md`](./config/README.md). This document is architecture, invariants, and review criteria. Don't duplicate the README here.

## Endpoints

| Path | Mechanism | Covers |
|---|---|---|
| `/rbac` | `ValidatingWebhookConfiguration` (admission) | CREATE / UPDATE / DELETE on the five tiered policy resources |
| `/authz` | `AuthorizationConfiguration` webhook authorizer (SubjectAccessReview) | GET / LIST / WATCH on the same five |
| `/cluster-info` | admission handler | writes to `ClusterInformation` from anything but `calico-node`, `calico-typha`, `calico-kube-controllers` |
| `/readyz` | plain HTTP | policy tier cache sync (always ready when `--authz-enabled` is off) |
| `/metrics` | Prometheus | see [Metrics](#metrics) |

The five tiered policy resources are `networkpolicies`, `globalnetworkpolicies`, `stagednetworkpolicies`, `stagedglobalnetworkpolicies`, `stagedkubernetesnetworkpolicies` (`tierauth.tieredPolicyResources`).

The split between `/rbac` and `/authz` is forced, not chosen. Admission is never invoked for reads, so an admission webhook cannot see a GET, LIST or WATCH at all. An authorization webhook sees every verb but only ever sees request attributes, never an object body, so it cannot authorize a CREATE whose tier is only knowable from `spec.tier`. Each path covers what the other structurally cannot.

`/cluster-info` is served unconditionally but nothing in `charts/calico` registers a webhook for it, so it is dead weight in a chart install today.

`/authz` is gated on `--authz-enabled`, off by default and set by the chart from `authzWebhookEnabled`. Off, the path is still registered but answers `NoOpinion` for everything, and the policy tier cache does not run. The path stays registered because an unregistered one 404s, the API server counts a 404 as a webhook failure, and under `failurePolicy: Deny` that denies every `projectcalico.org` request in the cluster. So the two halves of the install (the flag, and `--authorization-config` on the API server) can be done in either order without an outage in between.

### Review notes

- Adding an endpoint means adding it to this table. The `/authz` and `/rbac` split is load-bearing: a new verb belongs on the path that can actually see it.
- One TLS listener serves everything, `/metrics` included, so the listener's client-auth settings apply to scrapes as well. The README covers what that does to a Prometheus job.

## The shared decision core

All tier decisions live in `webhooks/pkg/tierauth`. `/rbac` and `/authz` are transports: they translate an `AdmissionReview` or a `SubjectAccessReview` into a `tierauth.Request`, and translate the `tierauth.Result` back. Neither holds authorization logic beyond deciding which requests it handles at all.

That's the whole reason `tierauth` exists. Two hooks enforcing the same rule from two different wire formats is exactly the shape that drifts, and a drift here is a security bug that only shows up on one verb.

`tierauth` delegates the actual RBAC evaluation to `apiserver/pkg/registry/projectcalico/authorizer.TierAuthorizer`, the same code the aggregated API server uses. So a v3-CRD cluster and an aggregated cluster answer the same question with the same code.

One consequence worth knowing: `TierAuthorizer` answers by issuing SubjectAccessReviews of its own, for `tiers` (verb `get`) and for `tier.<resource>`, both in the `projectcalico.org` group. The API server authorizes those SARs through its full authorizer chain, which includes this webhook. `matchCondition` 1 matches on group alone, and the exempt-identity `matchCondition` tests the SAR's *subject*, not the webhook's service account, so the webhook is re-entered. It answers `NoOpinion` immediately (neither `tiers` nor `tier.networkpolicies` is a tiered policy resource), so the recursion stops at depth two, but it isn't free: a policy read costs roughly three webhook round trips rather than one.

### Review notes

- New tier logic goes in `tierauth`, not in a hook. A rule that only one transport enforces is a bug even when both hooks look right in isolation.
- `tierauth.Request` is the boundary. If a hook needs to pass something new, add a field rather than branching on which hook is calling.
- Changing the SARs `TierAuthorizer` issues changes the re-entry behavior above. Check it still terminates.

## The never-Allow invariant

**`/authz` returns Denied or NoOpinion. Never Allowed.** This is the single most important thing not to break in this component.

Authorizers in the chain are OR'd, and this one sits ahead of RBAC (`Node -> calico-tiered-rbac -> RBAC`). An `Allowed: true` would satisfy the whole chain on its own and hand the user base resource permissions they were never granted. Tier enforcement is strictly subtractive: it can subtract access from what RBAC would allow, never add.

`DecisionPermitted` therefore maps to `NoOpinion` on the wire, not to Allowed. "Permitted" means "tier RBAC has no objection", and RBAC still has to agree.

The invariant is easy to hold and easy to break, because `SubjectAccessReviewStatus`'s zero value (`Allowed: false, Denied: false`) *is* NoOpinion. A one-line change that sets `Allowed` from a Permitted decision looks like a tidy-up and is a privilege escalation. `webhooks/test/authz/authz_test.go` covers it with a user who is authorized for the tier and has no `networkpolicies` permission at all: the list has to fail, with RBAC's message and not ours.

### Review notes

- Any change touching the `SubjectAccessReviewStatus` encoding in `webhooks/pkg/authz` must preserve never-Allow. There is no valid reason for `Allowed: true` to appear in that package.
- The write path is the opposite: `/rbac` is an admission webhook, not an authorizer, and `Allowed: true` there means "admission has no objection". Don't reason about the two encodings interchangeably.
- `DecisionNotApplicable` from `/rbac` is an internal error, not a pass. That hook only registers for the five tiered kinds, so a "not a tiered policy resource" answer means something upstream is wrong.

## Tier resolution

A tiered read needs two separate RBAC grants, and conflating them is the usual way to misread this component. `TierAuthorizer` issues one check for `get` on `tiers` named for the tier in question, and one for the request's verb on `tier.<resource>` (matching either `<tier>.*` or the policy name as the client sent it). The request passes only if the `tiers` check and one of the `tier.<resource>` checks both allow (`AuthorizeTierOperation` in `apiserver/pkg/registry/projectcalico/authorizer/authorizer.go` builds the two checks and requires both). A grant on the policy resource itself, `networkpolicies` rather than `tier.networkpolicies`, is what RBAC evaluates after we return, and it is not what any of this reads.

The decision needs a tier. How it gets one differs by path:

- **`/rbac`** reads `spec.tier` out of the object body. On a tier move it authorizes both the old and the new tier, since taking a policy out of a tier is itself a tier operation.
- **`/authz`** on a *named* request (GET, or a get-by-name) resolves the name to a tier through `policycache`.
- **`/authz`** on a request narrowed to one tier by selector uses the selector. Both `spec.tier` field selectors and `projectcalico.org/tier` label selectors count, `In` with exactly one value. Anything else (a multi-value selector, `NotIn`, a raw selector string) yields no tier and falls through to the unnamed check below, which is the safe direction: an ambiguous selector is treated as "no tier named", not as one of the tiers it mentions.
- **`/authz`** on an unselectored LIST or WATCH sends an *unnamed* check to `AuthorizeTierOperation`, with both name and tier empty. An empty tier means the `tiers` check goes out with no resource name, and RBAC matches an unnamed check only against rules that carry no `resourceNames`, so it comes down to whether the user's grant on `tiers` (not on the policy resource) is restricted to named tiers. That is exactly the question "is this user unrestricted by tier". A tier-restricted user is denied, and the deny message tells them to add a tier selector.

That last one is a deliberate behavior change from the aggregated API server, which narrowed the response instead of refusing the request. The webhook sees request attributes, not stored objects: it can approve or deny a request, it cannot filter a response. Enumerating every tier and denying unless the user is authorized for all of them was considered and rejected, since it turns one decision into a per-tier fan-out and still can't produce the filtered list a user actually wanted.

### Review notes

- Widening `extractTierFromSelectors` to accept more selector shapes has to keep the "ambiguous means no tier" direction. Picking one tier out of a multi-tier selector would authorize against a tier the request isn't limited to.
- The unnamed check depends on `AuthorizeTierOperation`'s empty-name semantics. A change on the `apiserver` side there changes what an unselectored LIST means here.
- The deny message is user-facing text and the only place a user learns how to make the request succeed. Keep the selector hint in it.

## Policy tier cache

`webhooks/pkg/policycache` answers "which tier is this policy in" from metadata-only informers over the five resources, keyed on the `projectcalico.org/tier` label. Metadata-only because the label already carries the answer; there is no reason to hold policy bodies in memory.

Two fallbacks to a live GET, both counted by `policy_cache_fallback_gets_total`:

- `reason="miss"`, the object isn't in the cache. Falls back rather than denying, so a read-after-write doesn't produce a spurious Forbidden.
- `reason="unlabeled"`, the object is cached but carries no tier label, which happens for policies created before the tier-label `MutatingAdmissionPolicy` was installed.

A NotFound from the fallback GET becomes `DecisionNotApplicable`, so RBAC runs and the API server returns its usual 404. Any other error denies: this path is fail-closed.

The GVRs are `projectcalico.org/v3`, which is correct because in v3-CRD mode the CRDs are served at that group/version and Felix and kube-controllers read it directly (`libcalico-go/lib/backend/k8s/discovery.go`). If that were ever wrong, every lister lookup would error, and the symptom would be a `policy_cache_fallback_gets_total{reason="miss"}` rate matching the named-read rate, with the fallback GETs carrying the cost.

`Start` does not wait for the initial list, so the server listens while the cache warms up and `/readyz` can answer 503 with a reason. Blocking there instead would mean a cache that never syncs never listens, and an operator debugging it gets connection-refused rather than a diagnosable 503.

Serving early is safe because `TierForPolicy` refuses to answer until `HasSynced`, and a refusal denies. Two things it deliberately does not do in that window: it does not fall back to a live GET (an unsynced lister reports every policy as missing, so the fallback would put the whole cluster's read traffic on live GETs exactly when the API server can least afford it), and it does not return `ErrPolicyNotFound` (which means "the policy does not exist" and hands the request to RBAC). A background goroutine warns, naming the outstanding resources, so a cache that never syncs is not a silent 503.

### Review notes

- Readiness must gate on `HasSynced`, and so must `TierForPolicy`. `/readyz` alone is not enough: readiness only controls whether the pod takes Service traffic, and the API server reaches this webhook through a pinned ClusterIP either way.
- `WaitForSync` exists for the tests. Calling it from `registerHooks` would put the blocking behavior back and re-break the 503.
- Keep the informers metadata-only. Caching bodies for all five resources on every cluster is a memory regression for a value the label already holds.
- The cache and the chart's read grant are both gated on the authz feature (`--authz-enabled` / `authzWebhookEnabled`), and have to stay gated together. Granting without running wastes nothing; running without the grant means the cache never syncs, and under `failurePolicy: Deny` that denies the whole `projectcalico.org` group.
- When the cache is off, `registerHooks` passes a stub resolver that returns an error rather than a nil interface. Nil would panic on the first named read; an error denies. The stub must never return `tierauth.ErrPolicyNotFound`, which would be read as "policy does not exist" and hand the request to RBAC.

## Install prerequisites

These are hard requirements, not recommendations. Missing any of them means tier enforcement on reads silently does nothing, or the cluster deadlocks.

**Kubernetes 1.32 or later.** `webhooks/config/README.md` states the floor on `AuthorizationConfiguration` grounds. There's a second, independent reason: `/authz` resolves a tier from the SubjectAccessReview's `labelSelector` and `fieldSelector`, which the API server only populates when the `AuthorizeWithSelectors` gate is on (upstream: alpha 1.31 off by default, beta 1.32 on by default, locked GA 1.34). With the gate off, `extractTierFromSelectors` always returns `""` and every selectored LIST is treated as unselectored, so tier-restricted users lose read access entirely rather than gaining a bypass. Fails closed, but fails.

**The tier-label `MutatingAdmissionPolicy`.** `api/admission/tierlabel.mutatingadmissionpolicy.yaml` defaults `spec.tier` and maintains the `projectcalico.org/tier` label (`v3.LabelTier`) with an unconditional JSONPatch add, under `failurePolicy: Fail`. Tier resolution *trusts* that label, both in the cache and in the label-selector path, so the MAP is what makes it trustworthy. Without it, every named read falls back to a live GET, and a user can hand-set the label to a tier the policy isn't in. It does **not** cover `stagedkubernetesnetworkpolicies`, which has no `Tier` field and is always in the default tier.

**The service-account exemption.** Three identities are exempt in the `AuthorizationConfiguration`'s `matchConditions`: `system:serviceaccount:kube-system:calico-webhooks`, `:calico-node`, `:calico-kube-controllers`. This is required, not defensive. In `useV3CRDs` mode Felix and kube-controllers read the `projectcalico.org` group directly, so gating them under `failurePolicy: Deny` stalls *their* informer bootstrap whenever the webhook is unreachable. `calico-webhooks` is the one that deadlocks the webhook itself: its informers read the very resources it authorizes, so without the exemption it can never reach the sync it needs to answer. The list hardcodes `kube-system`, which matches the chart and does not match an operator install.

### Review notes

- Adding a resource to `tieredPolicyResources` means adding it to `policyGVRs`, to the MAP's `matchConstraints`, and to the `ValidatingWebhookConfiguration` rules. Miss the MAP and the new resource's tier label is never maintained.
- The exempt list and the chart's namespace are coupled. Moving `calico-webhooks` to another namespace without editing `matchConditions` deadlocks bootstrap.
- A new Calico component that reads the `projectcalico.org` group in v3-CRD mode may need adding to the exempt list. `calico-cni-plugin` is one that reads it (IP pools) and is not exempt today.

## The AuthorizationConfiguration

`webhooks/config/authorization-configuration.yaml` inserts the webhook as `Node -> calico-tiered-rbac -> RBAC`. Two fields carry more weight than they look like they do.

**`unauthorizedTTL` is a security parameter, not a performance knob.** It caches NoOpinion as well as Denied. `spec.tier` is mutable, so moving a policy into a restricted tier leaves a previously authorized reader holding a stale NoOpinion for up to this long. Shipped value is 30s. `authorizedTTL` is inert, because we never Allow. The value is mirrored by hand as `authzUnauthorizedTTL` in `e2e/pkg/tests/policy/tiered_rbac_reads.go`, which polls for longer than it.

**`failurePolicy: Deny` combined with a group-wide `matchCondition` gives a wide blast radius.** The first `matchCondition` filters on the whole `projectcalico.org` group with no verb or resource guard, so an unreachable webhook denies every verb on every resource in that group for every non-exempt identity: writes included, `IPPool` and `FelixConfiguration` included, and `calico-cni-plugin` (not exempt) included, so pod setup can fail too. `webhooks/config/README.md`'s break-glass section describes this accurately.

Whether to narrow that filter is **open**, deliberately:

- For narrowing to read verbs plus the five tiered resources: it shrinks the blast radius at no cost to enforcement, since the Go side already answers `NoOpinion` for everything else. It would also cut out the second-order `tiers` / `tier.<resource>` re-entry described above, which is most of the webhook's traffic.
- Against: a tiered resource added later would silently fall outside a narrowed filter and lose enforcement, with nothing to catch it. Group-wide plus Go-side `NoOpinion` is safe by default.

Both sides are real. Nobody has picked one.

### Review notes

- Every field access in `matchConditions` needs `has()`. A CEL evaluation error counts as a webhook failure, so under `failurePolicy: Deny` an unguarded expression denies the entire `projectcalico.org` group. This is the review note, not just a fact.
- Lowering `unauthorizedTTL` shrinks a real stale-permission window and puts the webhook in front of proportionally more reads. It's a tradeoff, not a tuning default. Change `authzUnauthorizedTTL` in the e2e specs in the same PR.
- Narrowing `matchConditions` is a correctness change, not a cleanup: it changes which requests are enforced, not just which are consulted.

## Metrics

Namespace `calico_webhooks`:

| Metric | Labels | Notes |
|---|---|---|
| `calico_webhooks_tier_decisions_total` | `decision`, `resource`, `verb` | `decision` is one of `permitted`, `denied`, `not_applicable` |
| `calico_webhooks_tier_decision_duration_seconds` | `resource`, `verb` | includes any fallback GET |
| `calico_webhooks_policy_cache_fallback_gets_total` | `resource`, `reason` | `reason` is `miss` or `unlabeled` |
| `calico_webhooks_policy_cache_initial_sync_timestamp_seconds` | none | set once at startup, not on resync |

Every label value above comes from a fixed set. Deny detail goes to a structured log line in `tierauth.authorize`, once, at the decision point, and not again in the hook.

### Review notes

- Tier, policy, namespace, and user names must never become metric labels. They're unbounded and attacker-influenced, and the deny log already carries them.
- One deny, one log line. `/authz` deliberately doesn't log, because `tierauth` already logged with every field the hook could add.

## Tests

Three layers, lowest first:

- **Unit**, `webhooks/pkg/...`, run by `make -C webhooks ut` (scoped to `./pkg/...` so it doesn't pick up the envtest suite). Decision logic, selector extraction, cache fallbacks, metric registration.
- **envtest**, `webhooks/test/authz/authz_test.go`, run by `make -C webhooks ut-authz` against a real `kube-apiserver` with a real `AuthorizationConfiguration`. This is the only layer that exercises the real CEL `matchConditions`, the real SubjectAccessReview encoding the API server sends, and the TTL caching. Anything that depends on the API server's behavior rather than ours belongs here.
- **Kubernetes e2e**, `e2e/pkg/tests/policy/tiered_rbac_reads.go`. The `RequiresReadPathTierRBAC` specs hold under either enforcement mechanism (aggregated API server or this webhook) and detect which is present; the `RequiresAuthzWebhook` ones assert webhook-specific behavior such as an unselectored LIST being refused.

Honest state: **the e2e specs have never been executed.** No install path deploys this webhook in kind today (`kind-authz-cluster-create` writes the `AuthorizationConfiguration` and pins an address, but does not deploy the chart with a matching `spec.clusterIP`), so the `RequiresAuthzWebhook` specs skip everywhere. The `RequiresReadPathTierRBAC` specs would run on an aggregated-API-server cluster, but haven't. Treat the envtest suite as the real coverage until that changes.

### Review notes

- A behavior that depends on the API server (CEL, SAR wire format, TTLs, the authorizer chain order) is not covered by a unit test with a fake. Put it in the envtest suite.
- `webhooks/config/authorization-configuration.yaml` is a file an operator copies onto control-plane nodes; nothing at build or run time reconciles it against the Go constants that assume its values. `webhooks/pkg/authz/config_drift_test.go` is that reconciliation, and covers `timeout` vs `decisionTimeout`, `unauthorizedTTL` vs `negativeCacheTTL`, and `unauthorizedTTL` vs the e2e specs' `authzUnauthorizedTTL`. A new constant that assumes a value from that file belongs in it.
- The e2e specs fail rather than skip when the run asked for them by name, so a pipeline that means to run them can't pass by skipping them. "Asked for by name" has to include `--label-filter`, not just `-focus`: our pipelines select by label expression, and a spec that only consults `-focus` can never tell that it was selected. `describe.ExplicitlySelected` covers both, and is what these specs call.

## Open questions

Observed state, not what documentation claims.

1. **Does reloading `--authorization-config` cover the referenced kubeconfig and CA bundle, or only the config file?** Unverified. Kubernetes documents the config file as reloading from disk without a restart; nothing in this branch tested that, and nothing tested whether a changed kubeconfig or CA file is picked up. `webhooks/config/README.md` says so and prescribes an apiserver restart as the fallback. Matters because break-glass depends on it.
2. **Blast radius of the group-wide `matchCondition`.** See [The AuthorizationConfiguration](#the-authorizationconfiguration). Open on purpose.
3. **No operator install path.** Verified against `tigera/operator@0a6dac02a`: `pkg/render/webhooks/render.go` grants the webhook only `create` on `subjectaccessreviews` and `get` on `tiers`, so the cache never syncs and the pod never goes ready; the rendered Service pins no `ClusterIP`, so the kubeconfig has no address to name; and everything renders into `calico-system` while the exempt identities are `kube-system` service accounts. Layering the chart on top of an operator install would give the cluster two webhook Deployments. See the README's "Operator-managed installs" section.
4. **Cert rotation is manual.** See the README.

Resolved during implementation, recorded so nobody re-litigates them:

- The tiered policy CRDs *are* served at `projectcalico.org/v3` in v3-CRD mode, so the cache's GVRs are right.
- `request.user` *is* a plain string in the SubjectAccessReview CEL environment (`k8s.io/apiserver/pkg/authorization/cel/compile.go`, `buildRequestType`), and a string `in` a list of strings type-checks. The exemption expression is correct as shipped.

## Cross-cutting review notes

- **Keep this document in sync with the code.** A change to the endpoint split, the decision core, the never-Allow invariant, tier resolution, the cache, the install prerequisites, the `AuthorizationConfiguration`, or the metrics must update the relevant section in the same PR. Exemptions: a bug fix restoring behavior this doc already describes, a mechanical refactor with no observable change, comment or log-message edits, dependency bumps. If in doubt, update.
- Install, break-glass, and rotation procedures belong in [`webhooks/config/README.md`](./config/README.md), not here.
- This component is in the authorization path of every `projectcalico.org` request on a cluster that installs it. Prefer denying to guessing, and prefer `NoOpinion` to allowing.
