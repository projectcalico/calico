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
Semaphore passes the hosting cluster between stages **two ways** — the whole
`BZ_HOME` via `cache` (for destroy) and just the kubeconfig via `artifact` (for
hosted). ArgoCI has neither, so both become GCS objects, keyed by
`ARGO_WORKFLOW_NAME` (run-unique) + `HOSTING_CLUSTER`:

    BLOB=gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME}/hcp/${HOSTING_CLUSTER}/hosting-bzhome.tgz    # whole BZ_HOME → destroy-hosting
    KCFG=gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME}/hcp/${HOSTING_CLUSTER}/hosting-kubeconfig    # just kubeconfig → hosted

The BZ_HOME tar is **contents-relative** (`-C "$BZ_HOME" .`; restore
`-C "$BZ_HOME"`), so the tar carries no absolute path — the restore side controls
where the tree lands. (setup-hosting and destroy-hosting are pinned to the *same*
`BZ_HOME` path — see the venv trap below — so the extracted tree, including the
`.local/venv` inside it, lands exactly where it was created.)

Provenance — this reproduces the Semaphore mechanism (`.semaphore/end-to-end/
scripts/`): `install.sh:20` caches BZ_HOME under `${WORKFLOW_ID}-hosting-
${HOSTING_CLUSTER}`; `global_epilogue.sh:175` pushes the kubeconfig artifact;
`global_prologue.sh:186/193` restores the cache and **repoints `BZ_HOME` to its
original path** (the key move — see the venv trap below); `:198` pulls the
kubeconfig artifact; `global_epilogue.sh:186-187` yanks the artifact + deletes
the cache after destroy.

- **setup-hosting** (epilogue): `tar czf - -C "$BZ_HOME" . | gsutil cp - "$BLOB"`
  **and** `gsutil cp "${BZ_LOCAL_DIR}/kubeconfig" "$KCFG"` (the scaffold sets
  `BZ_LOCAL_DIR=${BZ_HOME}/.local`; `bz` writes the cluster's admin kubeconfig
  there). Must **not** `bz destroy` (the hosting cluster must survive for hosted).
- **hosted** (prologue): `gsutil cp "$KCFG" "${BZ_LOCAL_DIR}/hosting-kubeconfig"`;
  export `OPENSHIFT_HOSTING_KUBECONFIG=${BZ_LOCAL_DIR}/hosting-kubeconfig`. Absent
  object ⇒ fail fast. The hosted job keeps its own fresh `BZ_HOME` for its hosted
  cluster; its epilogue `bz destroy` tears down **its** hosted cluster (normal).
- **destroy-hosting** (prologue): restore the hosting `BZ_HOME`
  (`gsutil cp "$BLOB" - | tar xzf - -C "$BZ_HOME"`) so `bz destroy` has the
  terraform state. Absent blob ⇒ nothing to destroy, exit 0. Epilogue `bz destroy`
  tears the hosting cluster down; then `gsutil rm "$BLOB" "$KCFG"` (only on
  destroy success).

### BZ_HOME must be pinned across hosting stages (the venv trap)
A restored Python **venv is not relocatable** — its `bin/pip` etc. hardcode the
absolute path of the dir it was created in. If setup-hosting and destroy-hosting
land on different `BZ_HOME` paths, `bz destroy` fails on
`.local/venv/bin/pip: no such file`. The scaffold default
`BZ_PROFILE_NAME=${ARGO_WORKFLOW_NAME}-${RANDOM_TOKEN1}` is random per step, so
the prologue **pins** it for hosting stages
(`HCP_STAGE == *-hosting → BZ_PROFILE_NAME=${ARGO_WORKFLOW_NAME}-hosting-
${HOSTING_CLUSTER}`), giving both stages the same `BZ_HOME` and letting the
restored venv resolve. This is how Semaphore avoids the trap too — its
`cache restore` puts `BZ_HOME` back at its original absolute path
(`global_prologue.sh:193`); we make the path deterministic instead of random.

Path-pinning is what makes the venv resolve. We **keep** Semaphore's post-restore
`pip install -r ${BZ_HOME}/scripts/requirements.txt` (its `global_prologue.sh:195`)
too — it refreshes destroy-time system deps and its purpose is not solely pathing,
so dropping it would be an unproven bet; it is made non-fatal (`|| warn`).

**Deviation from Semaphore:** line 195 also `export PROVISIONER=aws-openshift`.
We omit only that — `PROVISIONER` comes from the cron step's `env` (cert:
`aws-openshift`), keeping the script provisioner-agnostic so the local-kind
plumbing smoke can exercise the same path.

Ordering: `hosted depends: setup-hosting`; `destroy-hosting` is an `onExit`
handler, so it needs no `depends` — Argo runs it once after the workflow
regardless of outcome.

## Epilogue destroy gating (the subtle part)
`global_epilogue.sh`'s `bz destroy` must run for **hosted** (destroy the hosted
cluster) and **destroy-hosting** (destroy the hosting cluster), but be **skipped
for setup-hosting** (keep the hosting cluster alive). So gate:
`if HCP_STAGE == "setup-hosting": push hosting BZ_HOME, skip bz destroy; else:
bz destroy as normal`.

## Files touched
- `.argoci/scripts/body_standard.sh` — restore the two `HCP_STAGE` guards above.
- `.argoci/scripts/global_prologue.sh` — pin `BZ_PROFILE_NAME` for `*-hosting`
  stages (venv trap); `HCP_STAGE` branch: `hosted` pulls the hosting kubeconfig
  object + sets `OPENSHIFT_HOSTING_KUBECONFIG`; `destroy-hosting` restores the
  hosting `BZ_HOME`.
- `.argoci/scripts/global_epilogue.sh` — `setup-hosting`: push hosting `BZ_HOME`
  + kubeconfig, skip `bz destroy`; `destroy-hosting`: `bz destroy` then
  `gsutil rm` both objects; `hosted`/non-HCP: unchanged.
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
  skipped-teardown-on-failure/eviction gap). Confirmed empirically: the local-kind
  plumbing smoke's `onExit` step ran the full prologue+epilogue.
- **teardown ordering is safe.** `onExit` fires only after every DAG node reaches
  a terminal state — including each hosted cell's own epilogue `bz destroy` of its
  hosted cluster. So all hosted clusters are gone *before* destroy-hosting tears
  down the hosting cluster underneath them; no hosted-on-vanished-hosting race.
- **concurrency / `hcp-shared-hosting` naming is inherited from Semaphore, not
  introduced here.** `HOSTING_CLUSTER` is a `bz` cluster-name label; 3 hosted
  cells sharing one hosting cluster, and cross-run isolation of a fixed hosting
  name, are properties of the existing cert pipeline that `bz` owns. The GCS blob
  key adds `ARGO_WORKFLOW_NAME`, so per-run *state objects* never collide even if
  `bz`'s cluster naming does; anything beyond that is out of scope for a faithful
  port.
- destroy-hosting fails → hosting cluster leaks → shared cluster-leak reaper; blob
  left for retry.
- **`HOSTING_CLUSTER` is a fixed label set identically on all three cron steps**
  (it + `ARGO_WORKFLOW_NAME` form the shared blob key); this is an invariant.
- **blob leak** (workflow aborted before destroy-hosting runs) → one-time bucket
  lifecycle TTL (e.g. 7d) on `*/hcp/**` as the backstop, same as the standing
  argoci-artifacts policy.

## Validation
A throwaway local-kind cron on the smoke fork exercised the whole path
(setup-hosting → hosted → onExit destroy-hosting). Confirmed: both objects push;
hosted pulls the kubeconfig, provisions, and runs the monorepo e2e suite; the
`BZ_HOME` pin lands destroy-hosting on setup's path so the restored venv resolves
(before the pin: `venv/bin/pip: no such file`; after: pip is found and runs).
`onExit` gets the full prologue+epilogue.

The **restored venv depends on the runner's system Python matching the venv's
Python.** The local-kind smoke image ships system py3.7 but `bz` builds a py3.10
venv, so the restored venv's pip then dies on `ModuleNotFoundError: distutils.cmd`
inside `local-kind:destroy` — an image quirk of that step, not the handoff (a
*fresh* local-kind venv destroys fine; only the restored one trips it, and only on
the mismatched image). The real cert path is `aws-openshift`, whose runner has
matching Python (the existing non-HCP openshift cert job proves this) — the same
condition under which Semaphore's restore works. So on the target path the pin is
sufficient; full aws-openshift confirmation waits on AWS-creds onboarding.

## Open questions
1. Confirm `bz`'s aws-openshift provisioner honours `OPENSHIFT_CLUSTER_TYPE=HCP-
   hosting/HCP-hosted` + `OPENSHIFT_HOSTING_KUBECONFIG` from the ArgoCI runner (the
   non-HCP openshift cert job already uses aws-openshift — a check, not a risk).
2. Exact GCS push point for setup-hosting: end-of-body vs epilogue. Epilogue is
   safer (runs on failure via the EXIT trap) — used above.
3. Confirm the aws-openshift runner's system Python matches the `bz` venv Python
   (expected — non-HCP openshift cert already runs there), so the restored
   hosting venv resolves for `aws-openshift:destroy`. Verified only once a real
   aws-openshift HCP run is possible.
