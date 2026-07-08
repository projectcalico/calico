# HCP on ArgoCI: vendored scripts + GCS cross-stage handoff

## Goal
Run the OSS Calico **certification** pipeline's HCP (hosted control plane) stages
on ArgoCI. HCP is an OpenShift/HyperShift flow: a **hosting** OpenShift cluster
houses N **hosted** clusters. On Semaphore the flow lives in `banzai-utils`
(cloned at runtime) and hands state between pipeline stages via the Semaphore
`cache`/`artifact` CLIs — neither of which ArgoCI has. So: **vendor the HCP
scripts into the monorepo `.argoci/scripts/` and adapt them for ArgoCI**, with a
**GCS-backed** cross-stage handoff.

In scope: `certification.yml` runs HCP (`PRODUCT=calico`); part of the epic to
vacate tigera-delivery Semaphore.

## Terms & execution model
- **Scaffold scripts** — the shared `.argoci/scripts/*` every e2e job sources:
  `global_prologue.sh` → `body_standard.sh` (sets `${PHASES}` =
  `.argoci/scripts/phases`, sources `phases/*`) → `global_epilogue.sh`.
- **globalEpilogue runs via an EXIT trap** appended to the step, so it fires even
  when `body_standard.sh` `exit 0`s. Consequences this design relies on:
  - the HCP dispatch's `exit 0` does **not** skip the epilogue (junit publish,
    etc.), so `hosted` results still publish; **but**
  - `hcp.sh` must **not** set its own `trap … EXIT` (it would replace the
    epilogue's trap) — pushes are explicit (below).
- **All HCP steps are steps of one Argo workflow**, so they share
  `ARGO_WORKFLOW_NAME` (the blob key) and can express `depends`.
- **Secrets** (`$HOME/secrets`) are materialised by the prologue on **every** step,
  so they're present on all three HCP stages (they are NOT in the handoff blob).
- **Guard** — `check-scaffold-parity.sh`: diffs each script in its `PAIRS` list vs
  its `.semaphore/end-to-end/scripts/*` origin; an `UNPORTED` loop
  (`for extra in phases/hcp.sh …`) names Semaphore scripts with no ArgoCI port.
- **`bz`** — banzai CLI from the runner image; `bz provision/install/tests` for the
  aws-openshift provisioner carry the OpenShift tooling; the non-HCP cert jobs
  already exercise it.

## The HCP model (banzai-utils/ocp-hcp)
Multi-cluster profile tree under **`$HOME/bzprofiles/`** (`BZ_PROFILES_PATH`), not a
single `BZ_HOME`:
- **`hcp-${BZ_HCP_PREFIX}.status`** at the tree root lists actual cluster names
  (`hosting:` first, then `hosted:`). `BZ_HCP_PREFIX` is a random id from `hcp-init`;
  downstream scripts find the file via `find "$BZ_PROFILES_PATH" -maxdepth 1
  -name 'hcp-*.status'` and never need the prefix.
- one full bz profile **per cluster** (`bzprofiles/<cluster>/`: banzai-core clone +
  `Taskvars.yml` + `.local/`).
- scripts (no `cache`/`artifact`/`SEMAPHORE_*` — the Semaphore handoff was all in
  the wrapper): **hcp-init** (`bz init profile` hosting + `HOSTED_CLUSTERS` hosted,
  hosted init'd with `OPENSHIFT_HOSTING_KUBECONFIG=<hosting>/.local/kubeconfig`;
  writes `.status`), **hcp-provision** (loop `.status`, hosting first:
  `bz provision && bz install`), **hcp-test** (loop: `bz tests`; junit →
  `bzprofiles/.report/junit_<cluster>_1.xml`), **hcp-destroy/hcp-diags**.

`HOSTING_CLUSTER` (env) is a **fixed cron label used only for the blob key**, not a
cluster name.

## Adapting the vendored scripts
No Semaphore-CLI usage inside them, so adaptation is env/paths only:
`BZ_PROFILES_PATH=$HOME/bzprofiles`, `BZ_SECRETS_PATH=$HOME/secrets`,
`BZ_PATH=$(command -v bz)`; confirm the `find … hcp-*.status` discovery works.

## Stage split & wiring
Cron step names (authoritative for `depends`): `hcp-setup-hosting`,
`hcp-hosted-setup-and-tests`, `hcp-destroy-hosting`. The Semaphore
"setup"/"hosted" names are misleading — **all provisioning happens in
`hcp-setup-hosting`**; `hcp-hosted-setup-and-tests` only tests.

Each `hcp.sh` stage branch ends with its own `exit $rc`, so the step reflects the
real result (`body_standard.sh`'s trailing `exit 0` is never reached).

- **`hcp-setup-hosting`** (`HCP_STAGE=setup-hosting`):
  `hcp-init && hcp-provision; rc=$?; push_tree; exit $rc` — the `&&` propagates an
  `hcp-init` failure into `rc` (a failed init writes no `.status`, so without the
  `&&` the empty provision/test loops would false-green). `push_tree` runs
  **explicitly** after (success or fail; no EXIT trap — it would clobber the
  epilogue's), guarded by `[ -d "$BZ_PROFILES_PATH" ]`, so partial state is
  recoverable.
- **`hcp-hosted-setup-and-tests`** (`HCP_STAGE=hosted`,
  `depends: hcp-setup-hosting`): `pull_tree || exit 1` → `hcp-test; rc=$?` → copy
  `bzprofiles/.report/*.xml` into `${REPORT_DIR}` (epilogue publishes it) →
  `exit $rc`.
- **`hcp-destroy-hosting`** (`HCP_STAGE=destroy-hosting`, added here):
  `pull_tree` (absent blob ⇒ "nothing to destroy", exit 0) → `hcp-diags` →
  `hcp-destroy`; **on `hcp-destroy` success** `gsutil rm` the blob (on destroy
  failure, leave the blob so a retry/reaper can act on the same state).
  `depends: "(hcp-hosted-setup-and-tests.Succeeded || hcp-hosted-setup-and-tests.Failed || hcp-hosted-setup-and-tests.Errored) || (hcp-setup-hosting.Failed || hcp-setup-hosting.Errored)"`
  — runs after hosted reaches any terminal state, or if setup Failed/Errored
  (hosted never ran); does **not** start merely because setup succeeded (would
  race hosted). `.Errored` (pod eviction/infra) is included so teardown isn't
  skipped on that path; the shared cluster-leak reaper remains the final backstop.

`phases/hcp.sh` is sourced by `body_standard.sh` **only** inside the
`HCP_ENABLED=true` branch (before the normal provision/install/test phases), and
dispatches via `case "$HCP_STAGE"` with **no default** — so a non-HCP job never
reaches it and it is never sourced by the normal phase sequence.

## GCS handoff
One object per run (`ARGO_WORKFLOW_NAME` = run-uniqueness; one hosting per run):

    BLOB=gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME}/hcp/${HOSTING_CLUSTER}/bzprofiles.tgz

    push_tree:  set -o pipefail
      [ -d "$BZ_PROFILES_PATH" ] || { echo "[INFO] no tree to push"; return 0; }
      tar czf - -C "$(dirname "$BZ_PROFILES_PATH")" "$(basename "$BZ_PROFILES_PATH")" \
        | gsutil cp - "$BLOB"
    pull_tree:  set -o pipefail
      rm -rf "$BZ_PROFILES_PATH"                       # clean any retry leftovers
      if ! gsutil -q stat "$BLOB"; then return 1; fi   # caller decides fatal vs ok
      gsutil cp "$BLOB" - | tar xzf - -C "$(dirname "$BZ_PROFILES_PATH")"

`pipefail` fails the push if `tar` dies mid-stream. On pull-miss: `hosted` treats
it fatal (`exit 1`); `destroy-hosting` treats it as nothing-to-destroy (`exit 0`).

**Handoff payload = the whole tree, banzai-core clones included** (simplest,
correct). Size ≈ (1 hosting + N hosted) small profiles; acceptable over a streaming
`gsutil cp`. If it proves too slow, a follow-up can `--exclude` the re-clonable
banzai-core and re-init on pull — out of scope here.

Note: the blob contains kubeconfigs (credentials) under `.local/`, in the same
`argoci-artifacts` bucket as diags tarballs (which already carry credentials) — no
new exposure class.

**One-time bucket prerequisite:** a lifecycle TTL (e.g. 7d) on `argoci-artifacts`
covering the `*/hcp/**` prefix, as the leak backstop when explicit `gsutil rm`
doesn't run. Not per-run; a standing bucket policy.

## Interfaces / env (and where each is set)
- **Blob:** `gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME}/hcp/${HOSTING_CLUSTER}/bzprofiles.tgz`
  — gzipped tar of `${BZ_PROFILES_PATH}`.
- **cron step:** `HCP_ENABLED=true`, `HCP_STAGE`, `HOSTING_CLUSTER` (fixed label),
  `HOSTED_CLUSTERS` (count; used by `hcp-init` in setup only).
- **prologue (HCP branch):** `BZ_PROFILES_PATH=$HOME/bzprofiles`, `BZ_SECRETS_PATH`;
  absolute `${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/hcp` on `PATH`.
- **prologue (all jobs):** `ARGO_WORKFLOW_NAME`, `GS_BUCKET=argoci-artifacts`,
  `REPORT_DIR`, `GOOGLE_APPLICATION_CREDENTIALS`.

## Files touched
- **`.argoci/scripts/hcp/*.sh`** (new) — vendored from `banzai-utils/ocp-hcp/*`
  with the env/path adaptations above.
- **`.argoci/scripts/phases/hcp.sh`** (new) — stage dispatch + `push_tree`/`pull_tree`
  + `.report`→`REPORT_DIR` copy.
- `global_prologue.sh` — HCP branch sets `BZ_PROFILES_PATH`/`BZ_SECRETS_PATH`, adds
  `hcp/` (absolute) to `PATH`.
- `body_standard.sh` — `if [[ "${HCP_ENABLED}" == "true" ]]; then source "${PHASES}/hcp.sh"; exit 0; fi`.
- `global_epilogue.sh` — **guard the generic `bz diags`/`bz destroy` with
  `HCP_ENABLED != true`** (HCP owns its own per-cluster diags/destroy across
  stages; a per-step `bz destroy` would kill the hosting cluster `hosted` needs).
  The junit-publish path is unguarded (HCP feeds it via `REPORT_DIR`).
- `.argoci/cron/e2e-certification.yaml` — `HCP_ENABLED=true` (+ `HOSTED_CLUSTERS` on
  setup); add the `hcp-destroy-hosting` step with the `depends` above.
- **Guard:** `global_prologue.sh`/`body_standard.sh`/`global_epilogue.sh` **are** in
  `PAIRS`, so their new HCP branches widen the normalised diff vs the Semaphore
  origin. The guard is golden-snapshot based, so this is the sanctioned path:
  after editing, run `check-scaffold-parity.sh --update` and review the golden
  delta (the HCP branches become the accepted, reviewed ArgoCI-only adaptation).
  For `phases/hcp.sh`: do not add it to `PAIRS`; delete the `phases/hcp.sh` token
  from the `UNPORTED` loop and comment why (intentional ArgoCI-native wrapper).
  Vendored `hcp/*` are from banzai-utils, not `.semaphore/`, so outside scope.

## Edge cases & failure modes
- **setup fails mid-provision** → explicit `push_tree` still runs → destroy fires
  (fan-in on setup `Failed`) → tears down. `hcp-destroy` best-effort.
- **setup fails with no tree** → push guard skips → destroy pull-miss → exit 0.
- **hosted/hcp-test fails** → destroy still runs (fan-in incl. hosted `Failed`).
- **hcp-destroy fails** → residual clusters → shared cluster-leak reaper backstop
  (blob TTL only reaps the blob), as for every suite.
- **step retry on a dirty pod** → `pull_tree` `rm -rf`s `bzprofiles` before untar,
  so no stale-tree/duplicate-`.status` merge.
- **destroy vs hosted race** → prevented by the corrected `depends` grouping.
- **push integrity** → `pipefail` prevents a truncated blob (a mid-stream `tar`
  failure fails the pipe, so no partial upload returns 0). A push *failure* is
  non-fatal to the setup step's `rc` by design; a bad/missing blob surfaces at the
  `hosted` `pull_tree || exit 1` and, ultimately, the reaper.

## Open questions
1. Confirm `bz`'s aws-openshift provisioner runs end-to-end from the ArgoCI runner
   (non-HCP cert jobs already use it — a check, not a risk).
