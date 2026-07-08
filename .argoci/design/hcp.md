# HCP on ArgoCI: standard flow gated by HCP_STAGE + GCS hosting-state handoff

## Goal
Run the OSS Calico **certification** pipeline's HCP (hosted control plane) stages
on ArgoCI. Cert HCP is the **standard `body_standard.sh` flow gated by `HCP_STAGE`**
— `bz` provisions OpenShift hosting/hosted clusters based on `OPENSHIFT_CLUSTER_TYPE`.
The only ArgoCI gap is the cross-stage handoff: Semaphore passes the hosting
cluster between stages via `cache` (BZ_HOME) + `artifact` (hosting kubeconfig),
neither of which ArgoCI has. Replace that with a **GCS object**.

## Non-goals
- The `banzai-utils/ocp-hcp` multicluster orchestrator / the `HCP_ENABLED` path —
  the cert pipeline does **not** set `HCP_ENABLED` and does not use those scripts.
  (This supersedes the earlier vendor-ocp-hcp approach.)
- Byte-identity of the handoff transport (GCS ≠ cache/artifact); the per-stage
  test/provision behaviour is preserved.

## Model (from Semaphore certification.yml + body_standard.sh)
All three HCP jobs run `body_standard.sh`, gated by `HCP_STAGE ∈ {setup-hosting,
hosted, destroy-hosting}`; `bz` (aws-openshift provisioner) interprets
`OPENSHIFT_CLUSTER_TYPE` (`HCP-hosting`/`HCP-hosted`), `OPENSHIFT_VERSION`, and
`OPENSHIFT_HOSTING_KUBECONFIG`.

- **setup-hosting** (one job, `OPENSHIFT_CLUSTER_TYPE=HCP-hosting`): standard
  provision+install creates the **hosting** cluster; no tests (see guards). Push
  the hosting cluster's state to GCS.
- **hosted** (3-cell matrix on `OPENSHIFT_VERSION` = 4.20.1/4.19.17/4.18.27,
  `OPENSHIFT_CLUSTER_TYPE=HCP-hosted`): pull the hosting kubeconfig; standard
  provision+install+test creates **one hosted cluster of that version** on the
  hosting cluster and runs the cert suite. Cells are independent.
- **destroy-hosting** (an `onExit` handler, `HCP_STAGE=destroy-hosting`): restore
  the hosting cluster's state; skip provision/install; the epilogue's `bz destroy`
  tears the hosting cluster down. As an `onExit` step it runs **once after the
  whole workflow regardless of how the hosted cells finished** — so teardown is
  guaranteed and there is no fan-in `depends` to express. (`onExit` steps get the
  full `globalPrologue`/`globalEpilogue` wrapping, same as normal steps, so the
  restore + `bz destroy` fire as designed.)

Different hosting/hosted OCP versions are supported (`bz` takes them per job); the
3 versions come from the hosted **matrix**, each cell one cluster — not from any
multicluster loop.

### body_standard.sh guards (restore verbatim from Semaphore)
    # HCP hosting/destroy-hosting stages join an existing cluster; skip provision/install.
    if [[ "${HCP_STAGE}" != "hosting" && "${HCP_STAGE}" != "destroy-hosting" ]]; then
      source "${PHASES}/provision.sh"; source "${PHASES}/install.sh"
    fi
    ...
    # hosting stages only stand up infra for other jobs; they don't run tests.
    if [[ ${MCM_STAGE:-} == *-mgmt* || ${HCP_STAGE:-} == *-hosting* ]]; then exit 0; fi
So: setup-hosting → provision+install, then exit before tests (`*-hosting*`);
hosted → provision+install+test; destroy-hosting → skip provision/install, exit
before tests (teardown happens in the epilogue). The literal `"hosting"` value is
vestigial (no cert stage uses it) but kept for faithfulness.

## GCS handoff (replaces cache + artifact)
The hosting cluster state is the setup job's `BZ_HOME` (terraform state +
`.local/kubeconfig`). One object per run:

    BLOB=gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME}/hcp/${HOSTING_CLUSTER}/hosting-bzhome.tgz

The tar is **contents-relative** (`-C "$BZ_HOME" .`), not `basename`-anchored —
each stage's `BZ_HOME` has a different name (per-job `BZ_PROFILE_NAME`), so the
restore side must not depend on the setup job's dir name.

- **setup-hosting** (epilogue): after install, `set -o pipefail;
  tar czf - -C "$BZ_HOME" . | gsutil cp - "$BLOB"`. The epilogue must **not**
  `bz destroy` here (the hosting cluster must survive for hosted).
- **hosted** (prologue): `mkdir -p "${BZ_LOCAL_DIR}/hosting"; gsutil cp "$BLOB" - |
  tar xzf - -C "${BZ_LOCAL_DIR}/hosting" ./.local/kubeconfig`; export
  `OPENSHIFT_HOSTING_KUBECONFIG=${BZ_LOCAL_DIR}/hosting/.local/kubeconfig`. Absent
  blob (or missing that path) ⇒ fail fast. The hosted job keeps its own fresh
  `BZ_HOME` for its hosted cluster; its epilogue `bz destroy` tears down **its**
  hosted cluster (normal).
- **destroy-hosting** (prologue): restore the hosting state into `BZ_HOME`
  (`mkdir -p "$BZ_HOME"; gsutil cp "$BLOB" - | tar xzf - -C "$BZ_HOME"`) so
  `bz destroy` has the terraform state; absent blob ⇒ nothing to destroy, exit 0.
  Epilogue `bz destroy` tears the hosting cluster down; then `gsutil rm` the blob
  (only on destroy success).

Keyed by `ARGO_WORKFLOW_NAME` (run-unique) + `HOSTING_CLUSTER`. Ordering:
`hosted depends: setup-hosting`; `destroy-hosting` is an `onExit` handler, so it
needs no `depends` — Argo runs it once after the workflow regardless of outcome.

## Epilogue destroy gating (the subtle part)
`global_epilogue.sh`'s `bz destroy` must run for **hosted** (destroy the hosted
cluster) and **destroy-hosting** (destroy the hosting cluster), but be **skipped
for setup-hosting** (keep the hosting cluster alive). So gate:
`if HCP_STAGE == "setup-hosting": push hosting BZ_HOME, skip bz destroy; else:
bz destroy as normal`.

## Files touched
- `.argoci/scripts/body_standard.sh` — restore the two `HCP_STAGE` guards above.
- `.argoci/scripts/global_prologue.sh` — `HCP_STAGE` branch: `hosted` pulls the
  hosting kubeconfig + sets `OPENSHIFT_HOSTING_KUBECONFIG`; `destroy-hosting`
  restores the hosting `BZ_HOME`.
- `.argoci/scripts/global_epilogue.sh` — `setup-hosting`: push hosting `BZ_HOME`,
  skip `bz destroy`; `destroy-hosting`: `bz destroy` then `gsutil rm` the blob;
  `hosted`/non-HCP: unchanged.
- `.argoci/cron/e2e-certification.yaml` — the `hcp-setup-hosting` +
  `hcp-hosted-setup-and-tests` (matrix) steps already carry `HCP_STAGE`/
  `HOSTING_CLUSTER`/`OPENSHIFT_CLUSTER_TYPE`/`OPENSHIFT_VERSION`. Add
  **`hcp-destroy-hosting` as an `onExit:` entry** (env `HCP_STAGE=destroy-hosting`
  + `HOSTING_CLUSTER=hcp-shared-hosting`, `commands: body_standard.sh`) — no DAG
  step, no `depends`. **No `HCP_ENABLED`** anywhere.
- **Remove** the vendored `.argoci/scripts/hcp/*` and `phases/hcp.sh` from #13162.
- Guard: the scaffold edits widen the golden → `check-scaffold-parity.sh --update`
  + review (sanctioned path). No new `phases/hcp.sh`, so no UNPORTED change.
- `.argoci/design/hcp.md` — this doc.

## Edge cases & failure modes
- **setup-hosting fails.** `hosted depends: hcp-setup-hosting` (Argo default
  `.Succeeded`) so `hosted` doesn't run on setup failure — the "hosted pull fails
  fast" path is only the defensive case (blob absent/partial). setup's epilogue
  still pushes on the failure path (EXIT trap), so the `destroy-hosting` `onExit`
  handler has state to tear any partial hosting cluster down.
- hosted fails → its epilogue `bz destroy` tears down **its** hosted cluster.
- **teardown always runs** — `destroy-hosting` is an `onExit` handler, so Argo
  runs it after the workflow regardless of the hosted cells' outcomes (no
  skipped-teardown-on-failure/eviction gap).
- destroy-hosting fails → hosting cluster leaks → shared cluster-leak reaper; blob
  left for retry.
- **`HOSTING_CLUSTER` is a fixed label set identically on all three cron steps**
  (it + `ARGO_WORKFLOW_NAME` form the shared blob key); this is an invariant.
- **blob leak** (workflow aborted before destroy-hosting runs) → one-time bucket
  lifecycle TTL (e.g. 7d) on `*/hcp/**` as the backstop, same as the standing
  argoci-artifacts policy.

## Open questions
1. Confirm `bz`'s aws-openshift provisioner honours `OPENSHIFT_CLUSTER_TYPE=HCP-
   hosting/HCP-hosted` + `OPENSHIFT_HOSTING_KUBECONFIG` from the ArgoCI runner (the
   non-HCP openshift cert job already uses aws-openshift — a check, not a risk).
2. Exact GCS push point for setup-hosting: end-of-body vs epilogue. Epilogue is
   safer (runs on failure via the EXIT trap) — used above.
