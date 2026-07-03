# .argoci — OSS Calico e2e on ArgoCI

This directory carries everything ArgoCI needs to run the OSS Calico e2e suites,
migrated off Semaphore's scheduled e2e builds.

## Contents

- `scripts/` — the e2e lifecycle, ported from `.semaphore/end-to-end/scripts/`
  and adapted for ArgoCI (secrets via `createLocalSecret`, `CI_*` vars,
  `RELEASE_STREAM` from the checked-out branch, GCS artifacts; `bz` + cloud
  CLIs come from the runner image). `global_prologue.sh` → `body_standard.sh`
  (dispatches to `phases/*`) → `global_epilogue.sh`.
- `cron/*.yaml` — one condensed ArgoCI workflow per e2e suite, mirroring the
  corresponding `.semaphore/end-to-end/pipelines/*.yml` (same jobs, same
  schedule). `cc-argoci-handler` expands each into a full CronWorkflow (checkout,
  secret loading, node placement, dind, exit handler, notifications, labels,
  metrics), picked up automatically on merge to the default branch.

These crons and scripts are maintained **by hand** going forward: edit the
YAML (or the scripts) directly to change a suite's jobs, env, or schedule.

## Cron naming (branchless)

Cron filenames and their `generateName` carry **no branch** — `e2e-nftables.yaml`,
`generateName: e2e-nftables-`. The same file lives unchanged on `master` and on
every release branch; `cc-argoci-handler` appends the **deploy branch** to the
CronWorkflow's `metadata.name` when it expands the file. So one file becomes:

| Branch the file is on | Deployed CronWorkflow name |
|---|---|
| `master` | `e2e-nftables-master` |
| `release-v3.33` | `e2e-nftables-release-v3-33` (branch sanitised: `.` → `-`) |

This is required because all crons share the single `argoci` namespace and are
applied upsert-by-name: without the branch qualifier, `master` and a release
branch's copy of the same file would collide. Deriving the branch at deploy time
(rather than baking it into the filename) means a file carried onto a release
branch by a cut is correct with no rename.

**The live object's name is therefore not visible in the file.** When looking for
a suite's cron in the `argoci` namespace, remember the handler appended the branch
(and sanitised any `.`/`/`). Keep `generateName` branchless — a baked-in branch
would double up (`…-master-master`) or, worse, collide across branches.
