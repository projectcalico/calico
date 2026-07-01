# Semaphore → ArgoCI e2e pipeline migration

Status: DRAFT v3 (scope = all active streams; dual-mode; Semaphore retirement)
Owner: Lance
Reference pipeline: `.semaphore/end-to-end/pipelines/nftables.yml`
Target convention: `tigera/banzai-service` `.argoci/` (CronWorkflow house style)

---

## Goal

Migrate **all** OSS Calico *scheduled* e2e pipelines from Semaphore CI to
ArgoCI (Argo Workflows on `argoci.dev.calicocloud.io`), across **all active
branches** (`master`, `release-v3.32`, `release-v3.31`), **starting with
`nftables.yml`** as the proving case. This is **time-critical: Semaphore is
being retired soon**, so the deliverable is a **repeatable Go converter +
skill** that converts every pipeline × branch the same way.

All workflow definitions and supporting scripts live **in
`projectcalico/calico` under a new `.argoci/` directory** — mirroring
`.semaphore/` today. ArgoCI is pointed at calico's `.argoci/`.

## Non-goals

- **PR-triggered e2e** — only scheduled pipelines. (PR e2e with cloud secrets
  on a public repo is a separate security review.)
- **Changing test behavior** — conversion is **faithful**; same tests, same
  provisioners, same matrix, same `bz` flow.
- **Enterprise/Calico-Cloud pipelines** — scope is OSS calico.
- **Replacing `bz`.**
- **Backporting the `testconfig` mechanism to release branches ("Option 3").**
  Deferred, and *not required*, because the converter is dual-mode (below).
  If pursued later to unify on `E2E_TEST_CONFIG`, it's cheap: backport
  `e2e/pkg/testconfig` + `e2e/config/`, then re-run the converter (a pure
  function of the source pipeline) to regenerate the release crons. The
  dual-mode `K8S_E2E_FLAGS` path then becomes vestigial.
- **Decommissioning Semaphore itself** (the act of turning it off) — this
  work makes ArgoCI ready; cutover is the trigger.

## Glossary & assumptions (read first)

- **`bz`** — the "banzai" CLI that provisions/installs/destroys test clusters
  (`bz provision|install|destroy|tests`). **Pre-installed in the ArgoCI base
  image**; not installed in the prologue. `PROVISIONER=local-kind|gcp-kubeadm|
  aws-eks|aws-talos|…` selects the backend; provider specifics live in `bz`.
- **`checkout`** — an ArgoCI-platform shell function (from the base image,
  not a repo file). `source checkout` clones the target repo into `/src`,
  setting `CI_HOME=/src`, `CI_GIT_DIR=<repo dir>`. Every template begins with
  it.
- **`RELEASE_STREAM`** — `master` | `v3.32` | `v3.31`. Selects which
  hashrelease e2e binary + product build is provisioned/tested; scheduled runs
  **download the per-`RELEASE_STREAM` e2e binary** (they don't build it).
  **Derived from the checked-out branch** (`release-vX.Y` → `vX.Y`, else
  `master`), per the per-branch-checkout strategy below — not a parameter.
- **`onExit`** — Argo `spec` field naming a template that runs once after the
  workflow finishes (success/failure/termination). Our cleanup safety net.
- **dind** — a `docker:*-dind` sidecar (`DOCKER_HOST=tcp://127.0.0.1:2375`).
  Required: `run_tests.sh` runs the e2e binary via `docker run`, and
  `local-kind` runs the cluster in-pod via Docker.
- **skill** — a Claude Code skill: the human-in-the-loop wrapper that drives
  the Go converter and hand-tunes irregular cases. Uses the repo's
  `e2e-tests` skill for config-file authoring.
- **Secrets** (`envFrom.secretRef`, must exist in `argoci` ns):
  `banzai-secrets` (GITHUB_ACCESS_TOKEN, cloud creds), `marvin-github-ssh-
  private-key`. Materialized to files in the prologue via `createLocalSecret`.
- **Test selection is dual-mode** (see below): `E2E_TEST_CONFIG` structured
  config files (*currently* `master` new-style + KubeVirt blocks; release
  branches can adopt later) *or* `K8S_E2E_FLAGS` focus/skip regex (*currently*
  release branches + most of `master`). The converter **passes through
  whichever the source job declares** — which is what enables incremental
  `E2E_TEST_CONFIG` adoption per stream.
- **Schedules are NOT in the repo** — Semaphore e2e pipelines run via
  Semaphore *Tasks* configured in the UI. So the cron schedule is an
  **explicit converter input** (`--schedule`).

## Background: how ArgoCI runs a repo's files

(Confirmed from `banzai-service/.argoci/config.yaml`, `ciworkflow.yaml`,
`cron/tesla-tests.yaml`.)

- ArgoCI is **multi-repo**: a repo is *onboarded*, then `.argoci/config.yaml`
  declares `ciFile:` + `changes.in/exclude` path filters.
- Scheduled suites are `kind: CronWorkflow` in `.argoci/cron/*.yaml`, ns
  `argoci`, with `spec.schedules` + `timezone`, `concurrencyPolicy: Forbid`,
  history limits, `workflowMetadata.labels`.
- Each template: `source checkout` → `source global_prologue.sh` → `<body>`
  → `source global_epilogue.sh` → `exit $CI_EXIT_CODE`; `onExit: exit-handler`
  guarantees cleanup. A `dind` sidecar provides Docker.

## Approach

### Central insight

The **lifecycle is constant** across pipelines and streams. Only the
**block/job/matrix/env tree** and the **selection mechanism** differ. So:

1. **Foundational, authored once by hand**: shared lifecycle in `.argoci/`.
2. **Per-(pipeline × branch), automated** by the Go converter: read
   `.semaphore/end-to-end/pipelines/<name>.yml` from a given branch → emit
   `.argoci/cron/e2e-<name>-<stream>.yaml`.

### Runtime/branch strategy (DECIDED: per-branch checkout)

**Each cron checks out its own target branch** (`branch: master` |
`release-v3.32` | `release-v3.31`), runs *that branch's* `.argoci/` tooling
and e2e tree, and tests that stream. `RELEASE_STREAM` is **derived from the
checked-out branch** (as `global_prologue.sh` does today: `release-vX.Y` →
`vX.Y`, else `master`) — not passed as a parameter. This is faithful to the
Semaphore per-branch model and avoids any master-tooling-vs-release-binary
mismatch.

**Consequence:** the `.argoci/` scaffold (scripts + `config.yaml` +
`ciworkflow.yaml` + the stream's `cron/*.yaml`) must exist **on every active
branch**. It is authored on `master` and **cherry-picked to `release-v3.31`
and `release-v3.32`** (mechanical; the scaffold is CI tooling). Each active
branch is onboarded and its crons synced (see Cron registration + Open
questions). The shared `e2e-test` `WorkflowTemplate` carries **no
branch-specific logic** — it only references scripts by path
(`${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/...`) resolved at runtime against
the checked-out branch. So it is applied to the `argoci` ns **once (from
master)** and every branch's crons `templateRef` it; behavior stays
branch-accurate because the *scripts* come from each cron's own checkout.
Consequently release branches must carry `.argoci/scripts/` + their own
`.argoci/cron/*.yaml` + `config.yaml`/`ciworkflow.yaml`, but need **not**
re-apply the template.

### Per-job model (vars-blob)

Each Semaphore job (after matrix expansion) → **one Argo DAG task** that
`templateRef`s the shared `e2e-test` template, passing its **entire merged
environment as one `test-vars` parameter** (`export K=V` lines). Precedence
(later overrides earlier), reading these exact Semaphore fields:
pipeline-level `global_job_config.env_vars` ⊕ block `task`-level `env_vars` ⊕
job `env_vars` ⊕ `matrix` axis values.

### test-vars injection (exact mechanism)

```yaml
# in the shared e2e-test WorkflowTemplate:
script:
  env:
    - name: TEST_SETTINGS
      value: '{{inputs.parameters.test-vars}}'
  source: |
    source checkout
    printf '%s\n' "$TEST_SETTINGS" > /tmp/test-vars
    source /tmp/test-vars
    export CI_EXIT_CODE=0
    source ${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/global_prologue.sh
    cd ${CI_HOME}/${CI_GIT_DIR}
    .argoci/scripts/body_standard.sh || CI_EXIT_CODE=1
    source ${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/global_epilogue.sh
    exit ${CI_EXIT_CODE}
```

### Test selection: DUAL-MODE (the key v3 change)

The converter emits **whichever mechanism the source job declares** — this is
what lets us convert master *and* release branches faithfully:

**Mode 1 — `E2E_TEST_CONFIG`** (source job sets `E2E_TEST_CONFIG`; used by
master new-style + all KubeVirt blocks). Emit
`export E2E_TEST_CONFIG='e2e/config/<variant>.yaml'`. Selection lives in a
structured config file (schema `e2e/pkg/testconfig`):
- `extends: <path>` — inherit a parent (usually `base.yaml`).
- `include: [ <label-expr> | {label, reason} ]` — Ginkgo label expressions,
  OR'd (the old focus).
- `exclude.labels: [ {label, reason(REQUIRED)} ]` — AND'd negations.
- `exclude.namePatterns: [ {pattern,reason} | {group,link,patterns[]} ]` —
  regex via `--ginkgo.skip`, for upstream tests lacking labels.

**Mode 2 — `K8S_E2E_FLAGS`** (source job sets `K8S_E2E_FLAGS`; release
branches + most of master today). Emit the flag string verbatim. **Escaping
rule**: the `test-vars` blob is a YAML **literal block scalar** (`|`); each
line is `export VAR='<value>'` in **single quotes**, so the shell treats the
value literally — backslashes, `(`, `|`, `[`, `\b` survive untouched.
Matrix values use `{{item.X}}` *inside* the quotes. A literal single quote
(rare) is emitted as `'\''`.

Worked example — release-branch job (Mode 2):
```yaml
- name: test-vars
  value: |
    export DATAPLANE='CalicoNftables'
    export KUBE_PROXY_MODE='nftables'
    export K8S_E2E_FLAGS='--ginkgo.focus=(\[sig-calico\]|\[Conformance\]) --ginkgo.skip=(\[Slow\]|\[Disruptive\]|sig-node|...|DNS.qualified.names.for.services)'
    export CLUSTER_IMAGE='{{item.CLUSTER_IMAGE}}'
```

**Incremental E2E_TEST_CONFIG adoption on master** (parallel, NON-blocking
quality track): translate a master job's `K8S_E2E_FLAGS` → an
`e2e/config/*.yaml` (label vs namePattern is judgment; use the `e2e-tests`
skill). Most variants are `extends: base.yaml` + small deltas (native-CRD
adds `exclude RequiresCalicoAPIServer`; the WG job includes `WireGuard`;
EKS-calico adds the `namePatterns` group). Once master's pipeline declares
`E2E_TEST_CONFIG`, the converter emits Mode 1 automatically on the next run —
no converter change. `base.yaml` currently excludes `Feature:KubeVirt`
("Banzai infra not ready") — this migration is that infra; revisit once the
KubeVirt cron works.

### Migration path to full E2E_TEST_CONFIG (Option 3, future)

Dual-mode is the pragmatic starting point (gets us off Semaphore fast). The
end state is **every stream on `E2E_TEST_CONFIG`**, reached incrementally with
**low lock-in** — because the converter is a pure function of the source
pipeline, moving a stream is just "change the source + re-run the converter."

Per-stream steps to go full `E2E_TEST_CONFIG`:

1. **master** (already in progress, non-blocking): author `e2e/config/*.yaml`
   per variant; update master's pipeline jobs to set `E2E_TEST_CONFIG`. The
   converter then emits Mode 1 for master automatically.
2. **A release branch** (`v3.31`/`v3.32`), when/if desired:
   a. Backport `e2e/pkg/testconfig` + `e2e/config/` + the `run_tests.sh`/
      Makefile wiring to that branch. (The `.argoci/` scaffold is already
      present from the initial cherry-pick; this step is only the e2e-binary
      machinery.) *(This is the only substantial cost, and
      it is timing-independent — the same whenever done. It changes the
      release-stream e2e **binary**, which is CI-internal tooling, so it's a
      lighter release-policy call than a product-feature backport — but still
      the release owners'.)*
   b. Author that branch's `e2e/config/*.yaml` (translate its
      `K8S_E2E_FLAGS`).
   c. Update that branch's pipeline jobs to set `E2E_TEST_CONFIG`.
   d. Re-run the converter against that branch → its crons regenerate in
      Mode 1. (Mechanical.)
3. **Retire Mode 2**: once no source pipeline on any active stream emits
   `K8S_E2E_FLAGS`, delete the Mode-2 code path and the escaping rule from the
   converter. Until then it is inert for Mode-1 pipelines.

**Lock-in assessment:** nothing in the dual-mode design forecloses Option 3;
the only throwaway is the (small) Mode-2 converter path plus a mechanical
regeneration of the affected crons. The expensive part (backport + config
authoring) is identical cost whenever performed.

### Matrix → withItems (cartesian expansion)

Semaphore `matrix` (cartesian across axes) → compute the product, emit one
`withItems` dict per combination, `{{item.<axis>}}` into the blob. No matrix
→ task with `arguments` only, **`withItems` omitted**.

### Converter determinism rules (stable, golden-testable output)

- **No inference.** Every value comes from the env-merge layers. The
  converter never invents `DATAPLANE`, `PROVISIONER`, selection, etc.
- **Selection mode** = presence of `E2E_TEST_CONFIG` (Mode 1) vs
  `K8S_E2E_FLAGS` (Mode 2) in the merged env. If both appear, `E2E_TEST_CONFIG`
  wins and a `# CONVERTER-TODO: both set` marker is emitted.
- **Resource profile** keys off the merged `PROVISIONER`: `local-kind` →
  large, else small.
- **Unknown agent type** → small profile + `# CONVERTER-TODO` + non-zero exit.
- **Matrix axis ordering** = source order (cartesian odometer over it).
- **Slug collisions** → source-order walk; first keeps bare slug, rest get
  `-2`, `-3`, … (deterministic, idempotent).

### Task naming & dependency wiring

- Name = kebab-cased DNS-safe slug: one job/block → `<block-slug>`; multiple →
  `<block-slug>-<job-slug>`; collisions suffixed. (`nftables.yml` has
  duplicate block/job names — dedupe required.)
- Matrix jobs stay one task carrying `withItems`; downstream `depends`
  references the task name (Argo waits for all its items).
- Semaphore block `dependencies: [<name>]` → `depends:` = `&&` of the named
  block's task names. `nftables.yml` is all `dependencies: []` → independent.
  Converter rejects cycles at emit time.

### Resource profiles (machine-type → pod resources)

| Semaphore agent | Used by | Argo pod requests (STARTING — validate vs argoci nodes) |
|---|---|---|
| `c1-standard-1` | remote-cluster jobs (default) | cpu `1000m`, mem `2Gi` |
| `f1-standard-2` | `local-kind` (cluster in-pod) | cpu `3500m`, mem `12Gi` |

Shared template takes `cpu-requests`/`mem-requests` inputs (default small);
converter sets large only for `PROVISIONER=local-kind`. Cluster nodes may be
arm (via `bz`); the runner pod stays amd64.

### Lifecycle hooks

- **Per-task**: `global_prologue.sh` (setup) + `global_epilogue.sh` (diags,
  reports, **Lens upload**, `bz destroy`). Normal completion destroys that
  task's uniquely-named cluster.
- **`onExit: exit-handler`** (best-effort): a `bz destroy`-sweep step with
  `continueOn.failed: true`. **No Slack** (dashboard + Lens for results).
- **Standing janitor CronWorkflow** (real safety net for killed pods whose
  epilogue never ran): reaps aged clusters by name/label/age. Authored once.

### Cron registration (decided, PENDING ArgoCI-owner confirmation — URGENT)

Intent: editing `.argoci/` triggers a resync. Plan: calico's `ciworkflow.yaml`
(gated by `config.yaml` `changes.in: .argoci/cron/.*`) lints and **applies/
updates** the `CronWorkflow`s (`argo cron create/update`). PENDING: confirm
whether the platform already auto-applies crons from an onboarded repo. This
is on the Semaphore-cutover critical path.

### Foundational artifacts (authored on `master` in `projectcalico/calico/.argoci/`, then cherry-picked to active release branches)

- `config.yaml` — `ciFile: ciworkflow.yaml`; `changes.in` incl.
  `.argoci/cron/.*`, `.argoci/scripts/.*`, `e2e/config/.*`.
- `ciworkflow.yaml` — cron-sync workflow; modeled on
  `banzai-service/.argoci/ciworkflow.yaml`.
- `templates/e2e-test.yaml` — shared `WorkflowTemplate` (body above), dind
  sidecar, volumes, `cpu/mem` inputs. Referenced by every cron via
  `templateRef`.
- `templates/exit-handler.yaml` (or inline) — the sweep step.
- `scripts/global_prologue.sh`, `global_epilogue.sh` — **ported** from
  `.semaphore/end-to-end/scripts/`, de-Semaphore-ified (`SEMAPHORE_*` →
  `CI_*`/`ARGO_*`; `checkout`/`cache` → `source checkout` + GCS;
  `artifact push` → `gsutil cp gs://argoci-artifacts/...`; secrets via
  `createLocalSecret`; keep Lens; `bz` from base image).
- `scripts/body_standard.sh` + `phases/*` — re-homed; provisioner-agnostic.
- Janitor cron.
- Base image: `gcr.io/tigera-cc-dev/ci-base/ubuntu-cloud-providers:<ver>`
  (`bz`, `gcloud`, `aws`, `az`, `kubectl`, docker client).

## Interfaces / data shapes

### Converter CLI (Go, in `hack/argoci/`)

```
semaphore2argo \
  --in       .semaphore/end-to-end/pipelines/nftables.yml \
  --branch   release-v3.31 \        # target branch; sets cron `branch:`, output name;
                                    #   RELEASE_STREAM derives from it at runtime
  --schedule "0 3 * * 2" \          # REQUIRED (not in-repo)
  --name     e2e-nftables \         # default: e2e-<basename>
  --out      .argoci/cron/e2e-nftables-v3.31.yaml
```
Emits `# CONVERTER-TODO: <reason>` + non-zero exit for anything it can't
fully convert, so the skill knows exactly what to hand-tune.

### Internal IR

```
Pipeline{ name; blocks []Block }
Block{ name; dependsOn []string; env map[string]string; jobs []Job }
Job{ name; env map[string]string; matrix []Axis; timeoutSeconds int }
Axis{ varName; values []string }
Selection = E2E_TEST_CONFIG(path) | K8S_E2E_FLAGS(string)   # from merged env
```

### Generated CronWorkflow skeleton

```yaml
apiVersion: argoproj.io/v1alpha1
kind: CronWorkflow
metadata: {name: e2e-nftables-v3.31, namespace: argoci, labels: {repo: calico, branch: release-v3.31}}
spec:
  schedules: ["0 3 * * 2"]; timezone: UTC; concurrencyPolicy: Forbid
  failedJobsHistoryLimit: 3; successfulJobsHistoryLimit: 3
  workflowMetadata: {generateName: e2e-nftables-v3.31-, labels: {repo: calico, type: Nightly, branch: release-v3.31, dashboard: calico-oss}}
  workflowSpec:
    entrypoint: pipeline; onExit: exit-handler
    # branch = the target stream's branch; checkout + RELEASE_STREAM derive from it.
    arguments: {parameters: [{name: reponame, value: calico}, {name: repoURL, value: git@github.com:projectcalico/calico.git}, {name: branch, value: release-v3.31}]}
    nodeSelector: {role: argoci}; tolerations: [{key: argoci, operator: Exists}]
    templateDefaults:
      script: {image: <base>, command: [bash], workingDir: /src}
      podSpecPatch: |
        containers: [{name: main, envFrom: [{secretRef: {name: banzai-secrets}}, {secretRef: {name: marvin-github-ssh-private-key}}]}]
    templates:
      - name: pipeline
        dag: {tasks: [ <one task per job; templateRef e2e-test; withItems if matrix; depends if block deps> ]}
      - name: exit-handler
        steps: [[ {name: sweep-destroy, continueOn: {failed: true}, template: <sweep>} ]]
    metrics: {prometheus: [ workflow_details gauge ]}
# e2e-test lives in .argoci/templates/e2e-test.yaml, referenced via templateRef.
```

## Test strategy: job-parity harness (the "identical jobs" proof)

The definition of a **faithful** conversion: the generated ArgoCI crons
enumerate the **same set of test jobs, with the same resolved parameters**, as
the Semaphore pipelines. We prove it by enumerating both sides into a common
canonical form and diffing — the converter's CI acceptance gate *and* the
pre-cutover audit before any Semaphore pipeline is switched off.

**Prior art, already in-repo:** `.semaphore/end-to-end/report/
generate_e2e_report.py` (mirrored from `tigera/banzai-calico/report`) already
enumerates Semaphore jobs. It merges `default_env_vars` (the
`global_prologue.sh` defaults) ⊕ `global_job_config.env_vars` ⊕ block
`env_vars` ⊕ job `env_vars` ⊕ `cartesian(matrix)` and writes one CSV row per
resolved job: `file, block, job, provisioner, release_stream, installer,
manifest_file, encap, dataplane, k8s_version, ip_version, other_flags,
k8s_e2e_flags, run_frequency, run_time, node_os, kernel` (→ `output.csv`). Its
merge precedence is **identical** to the converter's IR — reassuring, and
reusable.

**Harness:**
1. **Sem enumerator** — reuse `generate_e2e_report.py` (source of truth):
   Semaphore pipeline(s) on a branch → canonical job CSV.
2. **Argo enumerator (NEW, in Go, independent of the converter)** — a Go
   tool in `hack/argoci/` (alongside, but sharing no code with, the converter)
   that reads the generated `.argoci/cron/*.yaml`; for each DAG task, expands
   `withItems`, parses the `test-vars` blob back into `K=V` (applying
   `{{item.X}}`), and emits the **same CSV columns**. It parses the emitted
   YAML fresh — it does **not** reuse converter internals — so `E_sem ==
   E_argo` is a genuine cross-check, not the converter grading its own
   homework. (Bonus: Sem-side is Python, Argo-side is Go — two *independent*
   implementations of the expand/merge agreeing is strong evidence.)
3. **Normalize + diff** — sort rows; canonicalize env; drop platform-only vars
   (the report already ignores `google_*`, job IDs, etc. — see its filter).
   Assert the Sem job-set == the Argo job-set **per branch**. Any added,
   dropped, or param-different job fails.

**Properties / notes:**
- Compares on **resolved params, not names** (Semaphore job names ≠ Argo task
  slugs), so the slug/dedupe scheme is irrelevant to parity.
- **Per-branch**: `E_sem(branch)` vs `E_argo(branch)`, since selection and
  `RELEASE_STREAM` differ per branch.
- **Selection column matches verbatim**: `K8S_E2E_FLAGS ↔ K8S_E2E_FLAGS`, or
  `E2E_TEST_CONFIG` path ↔ same path — the dual-mode pass-through guarantees
  it. When master later adopts `E2E_TEST_CONFIG`, *both* sides reflect it
  (the source pipeline changed), so parity still holds; the harness tests the
  **converter**, not the selection migration.
- The **CSV schema is the contract** between the Python Sem-side tool and the
  Go Argo-side tool: identical column order, value normalization, and
  ignore-list, so a plain sorted set-compare works cross-language. Define the
  canonical **significant-params set** = report columns + retained
  `other_flags`; both enumerators normalize to it. Infra vars (job IDs, GCS
  dirs, regions/zones, timestamps) are excluded — they legitimately differ.
  (If Python maintenance becomes a burden, the Sem-side can be reimplemented
  in Go too — but keeping it a separate impl preserves the cross-check.)
- This is also the strongest regression test for the converter's
  merge-precedence, cartesian-expansion, and escaping logic.

## Edge cases & failure modes

- **`K8S_E2E_FLAGS` quoting** — single-quote + literal-block rule; global
  value and EKS override must round-trip. Golden test.
- **`E2E_TEST_CONFIG` path resolution** — resolved against the checked-out
  *checked-out branch's* tree (e.g. `release-v3.31` or `master`); the
  referenced config file must exist on that branch.
- **Per-branch scaffold drift** — since each branch runs its own `.argoci/`,
  the scaffold must be kept in sync across master + release branches
  (cherry-pick fixes). Divergence = branch-specific breakage. Keep the
  scaffold small and stable.
- **`local-kind`** — same body; large profile + dind. In-pod kind vs
  `docker run --net=host` under one dind daemon is the real risk; validate
  the first KinD run.
- **Cleanup on cancel/timeout** — `activeDeadlineSeconds` may kill a pod
  before epilogue `bz destroy`; onExit sweep is best-effort, janitor cron is
  the durable net. Unique cluster names make reaping safe.
- **Secret availability** — required secrets must exist in `argoci` ns before
  first run; missing `secretRef` fails the pod.
- **`bz` version** — from base image; skew vs Semaphore's pinned
  `BZ_TASK_VERSION`. Override via env if ever needed; validate parity.
- **Duplicate block/job names** — slug/dedupe covered by golden test.
- **Degenerate inputs** — empty block → no task; single-value axis → one
  item; cyclic deps → converter errors.

## Open questions (external / to confirm) — several now URGENT

1. **[URGENT] Cron registration.** Platform auto-applies crons from an
   onboarded repo, or must `ciworkflow.yaml` do `argo cron create/update`?
   On the cutover critical path.
2. **[URGENT] Onboarding `projectcalico/calico`.** Not yet onboarded; on the
   critical path. Low secret-exposure risk for scheduled crons on `master`
   (trusted code). Where is the onboarding allowlist / who approves?
3. **[URGENT] Per-branch onboarding + cron sync.** Per-branch checkout means
   each active branch (master, v3.32, v3.31) must be onboarded and have its
   crons synced. Confirm ArgoCI supports per-branch onboarding of one repo and
   how the sync selects branch. Working assumption: each branch's
   `ciworkflow.yaml` applies **its own** crons (uniquely named per stream, e.g.
   `e2e-nftables-v3.31` vs `e2e-nftables-master`, distinguished by the `branch`
   label) into the shared `argoci` ns — confirm this is how per-branch sync
   behaves.
4. **Resource values** — validate the profile table against argoci nodes.
5. **Secrets** — confirm `banzai-secrets` / `marvin-github-ssh-private-key`
   (and cloud creds) are present/readable in `argoci` ns for calico.

## Work breakdown (post-design)

1. **[gating]** ArgoCI-owner sign-off: onboard `projectcalico/calico` (all
   active branches) + confirm cron-registration + per-branch sync + secrets in
   `argoci` ns.
2. Foundational `.argoci/` scaffold on master: ported scripts +
   `templates/e2e-test.yaml` (cluster-applied) + `config.yaml` +
   `ciworkflow.yaml` + janitor.
3. Go `semaphore2argo` converter (dual-mode, `--branch`) + golden tests
   (nftables: matrix, escaping, dedupe, deps, both selection modes).
4. **Job-parity harness**: the new **Go** Argo-side enumerator (in
   `hack/argoci/`, independent of the converter) + the normalize/diff against
   the Python `generate_e2e_report.py`, on a shared CSV schema. Wire as the
   converter's CI acceptance gate.
5. Skill wrapper: drives converter, resolves `CONVERTER-TODO`s, `argo lint`.
6. Generate nftables@master; **parity harness must diff-clean**; then dry-run
   on argoci and validate a real run vs Semaphore.
7. **Cherry-pick the `.argoci/` scaffold to `release-v3.32` and
   `release-v3.31`**; generate nftables@{v3.32,v3.31}; parity-check; dry-run.
8. Convert the remaining pipelines × active branches via the skill; parity-
   check each; cut over per pipeline; retire Semaphore.
9. **[parallel, non-blocking]** Incrementally adopt `E2E_TEST_CONFIG` on
   master (author `e2e/config/*.yaml` per variant with the `e2e-tests` skill);
   converter picks it up automatically (see "Migration path" above).
