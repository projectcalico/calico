# Un-forking `operator-cloud` into `tigera/operator`

Status: **in progress** — foundation landed, per-component work scoped below.

## Goal & context

`tigera/operator-cloud` is a long-lived fork of `tigera/operator` that adds Calico Cloud
("tesla") behavior. We want to delete the fork and bring its differences into `tigera/operator`,
gated so that cloud code only activates on a Calico Cloud install and **enterprise/OSS behavior is
unchanged**.

Prerequisite: [operator-cloud#1059](https://github.com/tigera/operator-cloud/pull/1059) (remove
Image Assurance + runtime security) must merge first. This plan is written against the
post-#1059 fork state (branch `bm-remove-container-security`), which is fully caught up to
`tigera/operator` master — the merge-base equals master tip, so **every** diff below is genuine
cloud-specific divergence, not version drift.

Total divergence: **125 files, +7299 / -232** (57 added, 67 modified, 1 deleted).

## Gating design (decided)

**Runtime `Cloud` flag**, not a build tag and not a CRD variant.

- Cloud mode is gated **solely by the `CALICO_CLOUD` environment variable** (`cloud.EnableCloudEnvVar`),
  set on the operator Deployment by the cloud installer. The operator never infers cloud mode by
  sniffing for a ConfigMap. `cloud.Load(ctx, cs)` returns `Options{Cloud: false}` (no error, no
  ConfigMap read, no watch) unless `CALICO_CLOUD` is truthy; a set-but-unparseable value errors.
- Only once cloud mode is enabled does `cloud.Load` read the `cloud-operator-config` ConfigMap (and
  `ELASTIC_EXTERNAL`/`ELASTIC_MIGRATION` env) for cloud config *values* — those drive behavior, they
  do not gate it.
- `cloud.Options{Cloud, ElasticExternal, ESMigration}` is folded into
  `options.ControllerOptions{Cloud, ElasticExternal, ESMigration}` in `cmd/main.go`.
- Controllers and render code activate cloud paths only when `opts.Cloud` is true. The fork ran
  these paths unconditionally because the whole binary was cloud — **the central migration task is
  to add `if opts.Cloud { ... }` guards** around each ported cloud behavior so it is inert in
  enterprise.
- Cloud render customizations follow the fork's existing pattern: a typed per-component extension
  struct (e.g. `render.ManagerCloudResources`) populated by the controller only in cloud mode and
  consumed by `*_cloud.go` "decorator" methods in the render package. (This matches the typed
  per-component extension-struct direction already preferred for the OSS/enterprise split.)

### Gating gotchas (must NOT be ported verbatim)

Several fork edits change shared code paths and would alter enterprise behavior if copied directly.
Each must be guarded by `opts.Cloud` (or an equivalent cloud-only field):

- `key_validator_config.go`: `RequiredEnv` unconditionally appends
  `CALICO_CLOUD_REQUIRE_TENANT_CLAIM=true` via `addCloudEnvs`. Must only emit when a cloud tenant
  claim is configured.
- `utils/auth.go`: `GetKeyValidatorConfig` gains an `addTenancyClaim bool` param — ripples to every
  caller. In the unified repo derive the bool from cloud mode (e.g. `opts.Cloud && !opts.MultiTenant`).
- `manager.go`: the OIDC `CNX_WEB_OIDC_AUTHORITY`/`CNX_WEB_OIDC_AUDIENCE` changes are cloud-only
  workarounds and must be gated. (The image-assurance/runtime-security namespace + deprecated-resource
  cleanups in `manager.go` are enterprise-safe and already partly upstream via #1059.)
- `cmd/main.go` leader-election timing (`LeaseDuration`/`RenewDeadline`/`RetryPeriod` ×4) — gated
  behind `cloudOpts.Cloud` (done).

## Progress log

- **Phase 0 (foundation)** — DONE, builds + unit-tested. Gate is the `CALICO_CLOUD` env var.
- **Phase 1 (shared helpers)** — DONE: `meta.DefaultCertificateDuration`, `elasticsearch.AddTenantId`,
  `test.ExpectVolumeMount` offset fix, `key_validator_cloud.go` (self-gating `addCloudEnvs` — emits
  cloud OIDC envs only when a tenant claim is configured), `auth_cloud.go` + `GetKeyValidatorConfig`
  `addTenancyClaim` param (all 5 callers updated: apiserver/packetcapture pass `false`;
  manager/compliance pass `opts.Cloud && !opts.MultiTenant`; monitor gained a `cloud` field). Tests pass.
- **Phase 2 manager** — DONE, builds + render/controller tests pass (incl. a new gated cloud render
  spec and a non-cloud negative test). `ManagerConfiguration.Cloud`/`CloudResources`; all decorators
  in `manager_cloud.go` early-return when `!cfg.Cloud`; controller runs `handleCloudReconcile` and
  `addCloudWatch` only when `opts.Cloud`. **Skipped** the fork's Image-Assurance-removal hunks in
  `manager.go`/`manager_test.go` — enterprise still ships IA (#1059 removed it from the fork only).
- **Phase 2 logstorage** — DONE, builds + all logstorage render/controller tests pass. Gated:
  linseed (`Config.Cloud`, cloud objects/deployment/`ELASTIC_INDICES_CREATION_DISABLED`), esgateway
  (`CloudConfig.Enabled` gate, cloud objects + deployment mods), kibana (`CloudKibanaConfigOverrides`
  global only populated by the cloud-gated elastic controller), kube-controllers (`TenantId` field +
  gated `TENANT_ID` env — **skipped** the fork's RBAC `create`/`update` widening on
  clusterroles/bindings as an unexplained privilege escalation), elastic controller (cloud-kibana
  override read behind `r.cloud`), external-elastic controller (`AddTenantId` behind
  `opts.Cloud && !MultiTenant`), dashboards controller (cloud single-tenant tenant-from-CloudConfig),
  and ES ILM (`SetILMPolicies(ctx, ls, cloud)` param gates `tweakILMPoliciesForCloud`). Each cloud
  controller gained a `cloud` field set from `opts.Cloud`; cloud ConfigMap watches gated on
  `opts.Cloud`.
- **Phase 2 remaining** — DONE, builds + all affected controller/render tests pass:
  - compliance: gated cloud OIDC-issuer egress NetworkPolicy (`Cloud` field + `compliance_cloud.go`).
  - fluentd: gated `setFluentdCloudEnvs` (`DISABLE_ES_*_LOG`); `Cloud` wired from logcollector controller (both Linux & Windows configs).
  - tiers: gated `cloudPatchTier` (strips `app.kubernetes.io/instance` label from allow-tigera tier).
  - intrusiondetection / policyrecommendation: gated single-tenant tenant-from-CloudConfig + cloud ConfigMap watch.
  - packetcapture / monitor: kvc `addTenancyClaim` gating (done in Phase 1).
  - **RBAC divergences — now GATED behind `Cloud` (resolved):**
    - `apiserver.go` `tigeraUserClusterRole` + `tigeraNetworkAdminClusterRole`: added `Cloud` field;
      when cloud, UISettings RBAC is per-user only (no `cluster-settings` group) and the `lma.tigera.io`
      resources include `runtime`; when not cloud, the RBAC is byte-identical to enterprise (verified by
      the existing apiserver render specs still passing). Controller sets `Cloud: r.opts.Cloud`.
    - `kube-controllers.go` `NewElasticsearchKubeControllers`: added `Cloud` field; cloud grants
      `create`/`update` on clusterroles/clusterrolebindings (cloud es-kube-controllers provisions
      managed-cluster RBAC), enterprise keeps read-only. es-kube-controllers controller sets `Cloud: r.cloud`.
  - **SKIPPED (not RBAC, not a cloud feature):** `intrusion_detection.go` render diff is only
    Image-Assurance cleanup (#1059); enterprise keeps IA, so it stays out.

### Cloud-path tests — DONE (core set)
Ported + passing (adapted to the runtime `Cloud` gate):
- `pkg/render/manager_cloud_test.go` (+ non-cloud negative case).
- `pkg/render/fluentd_cloud_test.go` (`Cloud: true`; + non-cloud negative case).
- `pkg/render/logstorage/kibana/kibana_cloud_test.go` (drives `CloudKibanaConfigOverrides`; AfterEach
  resets the global to avoid leaking into enterprise specs).
- `pkg/controller/logstorage/elastic/elastic_controller_cloud_test.go` (`r.opts.Cloud = true` on the shim).
- `pkg/controller/compliance/compliance_controller_cloud_test.go` (`opts.Cloud: true`).
- `pkg/controller/manager/manager_controller_cloud_test.go` (`TestEnv` — `cloudConfigOverride`).

While porting the compliance controller test I found **three gated `compliance_controller.go` changes
I'd missed** and added them: the cloud ConfigMap watch, the system-root trusted-bundle creation for
external-OIDC management clusters, and the tenant-from-CloudConfig block. Added an exported
`compliance.NewReconcilerWithShims` test constructor.

### Still outstanding
- Lower-value `_test.go` deltas (esgateway/linseed/logstorage/kube-controllers/users/external-elastic/
  es-kube-controllers/policyrecommendation cloud test cases) and the golden-YAML RBAC test infra
  (`render_suite_test.go` TestMain, `testsupport/golden_yaml.go`, `clusterrole` pkg, `.golangci.yml`,
  `manager-cloud-rbac-all-golden.yaml`). Functional code + enterprise safety already verified.
- Phase 3 (cloud version-gen wiring) and Phase 4 (cloud build/release pipeline).
- Decisions on the three SKIPPED items above.
- Run full `make ut` / CI before PR.

### Per-file judgment calls discovered (apply to remaining work)

- **Skip incidental refactors that aren't cloud features.** e.g. `pkg/render/logstorage.go` only changes
  `curatorDecommissionedResources` to use a helper — not cloud, would shift enterprise output. Don't port.
- **`elasticsearch.go` ILM gating is a real trap.** The fork calls `tweakILMPoliciesForCloud` from
  `SetILMPolicies` unconditionally, adding a `tigera_secure_ee_runtime` policy. Must be gated (thread a
  cloud flag onto `esClient`) or it changes enterprise ILM.
- **`kibana.go` uses a global var `CloudKibanaConfigOverrides`** the fork itself flags as wrong. Prefer
  threading it through the kibana `Configuration` rather than porting the global (empty default is
  enterprise-safe, but the pattern is bad and racy).
- **External-ES already skips the ES storage-class requirement** (`elastic_controller.go` returns early
  when `opts.ElasticExternal`), so cloud external-ES installs never need `tigera-elasticsearch`.

## Phased plan

### Phase 0 — Foundation ✅ DONE (this branch)

Behavior-neutral scaffolding; compiles and unit-tested, zero enterprise impact.

| File | Notes |
|---|---|
| `pkg/cloud/cloud.go`, `watch.go`, `cloud_test.go` | Ported; `Load` made tolerant — returns `Cloud:false` (no error, no watch) when no cloud config present. Added `Cloud` field + non-cloud test case. |
| `pkg/render/common/cloudconfig/{cloudconfig,*_test}.go` | Verbatim port (pure data type). |
| `pkg/controller/utils/cloudconfig.go` | `GetCloudConfig`, `GetTenantFromCloudAuthConfig`, `CloudAuthConfig` const. Unused until controllers are wired. |
| `pkg/components/cloud_images.go` | `CloudRegistry` const. |
| `config/cloud_versions.yml` | `cloud-rbac-api` source-of-truth. |
| `pkg/controller/options/options.go` | `+Cloud`, `+ESMigration` fields. |
| `cmd/main.go` | `cloud.Load` wired; `ElasticExternal ||= cloudOpts.ElasticExternal`; `Cloud`/`ESMigration` set; leader-election tweak gated; `verifyConfiguration` ESMigration early-return. |

Verified: `go build` + `go test ./pkg/cloud/... ./pkg/render/common/cloudconfig/...` pass; `go vet ./cmd/...` clean.

### Phase 1 — Shared cloud helpers (additive, low risk)

New packages/files used by later phases; harmless to enterprise on their own.

- `pkg/render/common/clusterrole/clusterroles.go` (new)
- `pkg/render/common/elasticsearch/multitenancy.go` (new)
- `pkg/render/common/meta/meta.go` (small additions)
- `pkg/render/testsupport/golden_yaml.go` + `pkg/render/common/test/testing.go` + `.golangci.yml`
  (test helper for golden-YAML cloud RBAC tests; the lint config only exempts this helper's dot-import)
- `pkg/controller/utils/elasticsearch_cloud.go` (new) + `elasticsearch.go` (gated edits)
- `pkg/controller/utils/auth_cloud.go` + `auth.go` `GetKeyValidatorConfig` signature (see gotchas)
- `pkg/render/common/authentication/.../key_validator_cloud.go` + `key_validator_config.go` (gated)

### Phase 2 — Per-component render + controller cloud paths (the bulk)

For each component: add the `*_cloud.go` decorator/helpers, add the typed `…CloudResources` field
to the render config, populate it in the controller **only when `opts.Cloud`**, and add cloud
ConfigMap watches. Gate every shared-file edit.

| Component | Render files | Controller files |
|---|---|---|
| **manager** | `manager.go` (M), `manager_cloud.go` (A) | `manager_controller.go` (M), `manager_controller_cloud.go` (A) |
| **logstorage / linseed** | `linseed/{linseed.go (M), cloud.go (A)}` | `linseed/linseed_controller.go` (M) |
| **logstorage / esgateway** | `esgateway/{esgateway.go (M), cloud.go (A)}` | `kubecontrollers/{esgateway.go, es_kube_controllers.go, cloud.go (A)}` |
| **logstorage / kibana** | `kibana/kibana.go` (M) | — |
| **logstorage (core)** | `logstorage.go` (M) | `elastic/{elastic_controller.go, external_elastic_controller.go}`, `dashboards/dashboards_controller.go`, `users` |
| **apiserver** | `apiserver.go` (M) | `apiserver/apiserver_controller.go` (M) |
| **compliance** | `compliance.go` (M), `compliance_cloud.go` (A) | `compliance/compliance_controller.go` (M) |
| **fluentd** | `fluentd.go` (M) | (tests: `fluentd_cloud_test.go`) |
| **intrusion detection** | `intrusion_detection.go` (M) | `intrusiondetection/intrusiondetection_controller.go` (M) |
| **kube-controllers** | `kubecontrollers/kube-controllers.go` (M) | — |
| **monitor / packetcapture / policyrecommendation / tiers** | — | respective `*_controller.go` (M) — mostly cloud config-map watches / tenant plumbing |

Plus the test files for each (`*_cloud_test.go`, `*_test.go` deltas, `render_suite_test.go`,
`test/mainline_test.go`, `pkg/render/testdata/manager-cloud-rbac-all-golden.yaml`).

Recommended ordering: manager → logstorage (linseed/esgateway/kibana/elastic) → apiserver →
compliance → fluentd/intrusiondetection/kubecontrollers → remaining controllers. Land each
component as its own PR with its tests, verifying enterprise golden files are unchanged.

### Phase 3 — Version generation wiring ✅ DONE

- `hack/gen-versions/main.go`: ported the `-cloud-versions` flag (and fixed the swapped os/ee help
  text); generation now requires exactly one of `-os-versions`/`-ee-versions`/`-cloud-versions`.
- Added `hack/gen-versions/cloud.go.tpl` (the fork's `-cloud-versions` flag was dead — no template
  existed). It generates `pkg/components/cloud.go` with `ComponentCloudRBACAPI` + `CloudImages` from
  `config/cloud_versions.yml`, referencing the hand-written `CloudRegistry` const in `cloud_images.go`.
- `Makefile`: added a standalone `gen-versions-cloud` target (`CLOUD_VERSIONS?=config/cloud_versions.yml`).
  **Intentionally NOT in the default `gen-versions` aggregate** so the enterprise build's generated
  output is byte-identical (verified: os/ee generation still match the committed calico.go/enterprise.go).
  No CRD-fetch dep (cloud relies on upstream operator for CRDs). The cloud release pipeline invokes it.
- Generated `pkg/components/cloud.go` is committed, gofmt-clean, compiles, and idempotent (dirty-check safe).
- `cloud-rbac-api` (cc-rbac-api) is not consumed by operator render code — it's a release-tooling image
  pin (the `cloud.go` component pin + the `CloudRegistry` const in `cloud_images.go`, which the cloud
  release tool patches). **Did NOT** edit the shared `enterprise.go.tpl` (the fork's tesla-prefixed
  Kibana/Manager + CloudRegistry kube-controllers edits would globally tesla-fy enterprise images).
  Cloud image overrides happen at runtime where wired (e.g. manager via `CloudResources.ManagerImage`);
  any further cloud image pinning (kibana/kube-controllers) is a Phase 4 build/release concern.

### Phase 4 — Cloud build/release pipeline

**Build/release tooling — DONE** (coexists with enterprise, verified):
- `hack/release/cloud.go` + `hack/release/internal/versions/cloud.go` + `hack/release/cloud_test.go`
  are guarded by the **`cloud` build tag**, so they compile only into the cloud release tool
  (`go build -tags cloud`). The enterprise/OSS release tool is byte-for-byte unaffected (verified:
  untagged build + tests pass unchanged). `cloud.go`'s `init()` reassigns the OSS package-level hooks
  (`isValidReleaseVersion`, `setupHashreleaseBuild`, `publishImages`, command `Before` funcs) — so
  `checks.go`/`flags.go` were **not** edited (unlike the fork, which swapped them globally).
- `Makefile`: `make release-cloud` / `make release-publish-cloud` build `hack/bin/release-cloud` with
  `-tags cloud`. A gated `ifeq ($(VARIANT),cloud)` block overrides image identity (GCR /
  `tigera-tesla/operator-cloud`, amd64-only) — verified that enterprise vars are unchanged when
  `VARIANT` is unset and switch correctly when `VARIANT=cloud`.
- `hack/release/CLOUD.md` documents the cloud release/hashrelease flow.

**CI pipelines — follow-up (not in this PR):** the Semaphore `cloud-v*` GCR push/release blocks and
the Argo hashrelease build + cluster-rollout workflows (`.argoci/`, `hack/hashrelease/*.py`) are
environment-specific (operator-cloud Semaphore project, ArgoCD apps, GCR service accounts) and won't
run until cloud CI is wired into this repo. The OBSOLETE fork-sync machinery is dropped entirely (see
classification below).

---

## CI / build / release / tooling classification

Each infra file sorted by disposition. **Do not bulk-copy** — most either don't apply or must be
made cloud-conditional.

### OBSOLETE — delete with the fork, do not migrate
- `.argoci/cron/operator-cloud-fork-maintenance-nightly.yaml` — nightly upstream→fork merge cron.
- `.argoci/templates/sync-operator-cloud-branches.yaml` — runs `hack/update_fork.sh` merge-back.
- `.argoci/templates/hashrelease/sync-operator-hashrelease-fork.yaml` — fork-sync half (build-kickoff survives elsewhere).
- `hack/update_fork.sh`, `hack/hashrelease/update_hashrelease_fork.sh` — fork merge-back automation.
- `.claude/skills/merge-operator-into-operator-cloud/SKILL.md` — fork-merge runbook.
- `.github/README.md` + `CLOUD_README.md` (symlink) — fork branch-maintenance docs.
- `.semaphore/approve_check.yml` — auto-approves bot fork-sync PRs.
- `.bulldozer.yml`, `.ccbot/config.yaml` — automerge config existing to service fork-sync (drop unless automerge is independently wanted).

### KEEP-ENTERPRISE — drop the fork's divergence
- `.github/workflows/codeql-analysis.yml` (fork deleted it — keep enterprise's CodeQL).
- `.github/CODEOWNERS` (fork made it `* @tigera/calico-cloud` — keep enterprise; add path-scoped cloud owners if desired).
- `.github/workflows/sync-versions.yml` (fork disabled the cron — keep enterprise's).
- `config/calico_versions.yml` (only a duplicated comment), `config/enterprise_versions.yml` (tesla wiring).
- `hack/gen-versions/enterprise.go.tpl` (tesla image edits — handle as cloud-scoped overrides instead).
- `git-hooks/pre-commit-in-container` (fork disabled the copyright check globally — don't).
- `api/go.mod` (module rename to `operator-cloud/api` — don't carry).

### TWEAK — migrate but make cloud-conditional (don't globally override enterprise)
- `Makefile` — cloud `REPO`/`BUILD_IMAGE`/`IMAGE_REGISTRY=gcr.io`/`PUSH_IMAGE_PREFIXES`/
  `EXCLUDE_MANIFEST_REGISTRIES`, `VALIDARCHES=amd64`, `gen-bundle`/`bundle-crd-options` (RH v1beta1).
  Gate behind a cloud variant so enterprise quay + multi-arch defaults survive.
- `.semaphore/{push_images,release,semaphore}.yml` — GCR auth/push, `cloud-v*` release trigger,
  `staging` promotions, disabled multi-arch block. Make additive/coexisting, not replacements.
- `hack/release/{checks,flags}.go` — swapped OSS version validation to cloud format globally;
  make variant-conditional.
- `hack/gen-versions/main.go` — `-cloud-versions` flag (additive but currently unwired; finish in Phase 3).
- `git-hooks/files-to-skip` — adds cloud `_cloud` files to deepcopy skip; migrate with the Go code.

### REPLACE — cloud capability needed, fork impl is fork-specific
- `.argoci/templates/hashrelease/build-hashrelease.yaml` — re-target build+push at unified repo.
- `.argoci/templates/hashrelease/update-cluster-with-hashrelease.yaml` + `hack/hashrelease/*.py` —
  live cloud-cluster rollout automation (single/multi-tenant/managed); re-home as a cloud pipeline.
- `hack/release/cloud.go`, `hack/release/internal/versions/cloud.go`, `hack/release/cloud_test.go`,
  `hack/release/utils_test.go`, `hack/release/CLOUD.md` — cloud extension of the shared release
  tool (GCR/tesla images, `cloud-v*` format, hashrelease flags, disabled GH release). Re-introduce
  as a cloud-gated extension rather than always-on `init()` registration.

### MIGRATE-ASIS — harmless, bring over
- `.github/workflows/secret_scanners.yml` (TruffleHog/gitleaks PR scan).
- `.golangci.yml` (only exempts the cloud golden-YAML test helper's dot-import).
- `.argoci/config.yaml` (`version: v2` marker).

### Cloud build/release capabilities to (re)implement (Phase 4 scope)
1. Cloud image identity & GCR registry overrides (Makefile), amd64-only, without touching enterprise quay/multi-arch.
2. Cloud GCR push/release Semaphore blocks triggered by `cloud-v*`, coexisting with enterprise `v*`.
3. Cloud release-tool extension (flags, `cloud-v*` validation, GCR/tesla images, hashrelease outputs).
4. Cloud version generation (`cloud.go.tpl` + `gen-versions-cloud`), cloud-scoped image overrides.
5. Cloud hashrelease build pipeline (Argo), re-targeted at the unified repo.
6. Cloud cluster rollout automation (Argo + `hack/hashrelease` python).

---

## Risks & verification

- **Enterprise regression** is the primary risk. Mitigation: every shared-file edit guarded by
  `opts.Cloud`; enterprise golden YAML / `_test.go` fixtures must be byte-identical before/after each
  PR. Run `make ut` and the render golden tests per component.
- **Cross-cutting signature changes** (`GetKeyValidatorConfig`) touch many callers — land with all
  call sites updated in one PR.
- **Dead/unwired fork code** (the `-cloud-versions` gen path) — finish wiring in Phase 3, don't
  copy it half-done.
- Keep `make gen-files` / `make dirty-check` green after any API/CRD-adjacent changes.
