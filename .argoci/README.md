# .argoci — OSS Calico e2e on ArgoCI

This directory carries everything ArgoCI needs to run the OSS Calico e2e
suites (the migration off Semaphore's scheduled e2e builds). It is the **only**
part of the migration that lives in this repo — the converter tooling lives in
the `semaphore-to-argoci` skill (tigera-de-tools plugin, claude-plugin-marketplace).

## Contents

- `scripts/` — the e2e lifecycle, ported from `.semaphore/end-to-end/scripts/`
  and adapted for ArgoCI (secrets via `createLocalSecret`, `CI_*` vars,
  `RELEASE_STREAM` from the checked-out branch, GCS artifacts; `bz` + cloud
  CLIs come from the runner image). `global_prologue.sh` → `body_standard.sh`
  (dispatches to `phases/*`) → `global_epilogue.sh`.
- `cron/*.yaml` — **generated** condensed ArgoCI workflows, one per Semaphore
  pipeline × stream. `cc-argoci-handler` expands each into a full CronWorkflow
  (checkout, secret loading, node placement, dind, exit handler, notifications,
  labels, metrics). Picked up automatically on merge.

## Do not hand-edit `cron/*.yaml`

They are generated from `.semaphore/end-to-end/pipelines/*.yml` by the
`semaphore-to-argoci` skill and verified job-for-job against the Semaphore
source by its parity harness. To change a pipeline, edit the Semaphore source
(or the scripts here) and regenerate:

```
semaphore2argo --in .semaphore/end-to-end/pipelines/<name>.yml \
  --branch <branch> --schedule "<cron>" --out .argoci/cron/e2e-<name>-<stream>.yaml
```

> **Note:** `semaphore2argo` ships in the Tigera-internal `semaphore-to-argoci`
> skill (tigera-de-tools plugin), not on an OSS contributor's PATH — regeneration
> is a Tigera-internal step. External contributors should edit the Semaphore
> source (or the scripts here) and ask a Tigera maintainer to regenerate.
