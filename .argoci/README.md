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
  metrics), picked up automatically on merge to the default branch. The one
  exception to the mirroring is `cron/e2e-openstack.yaml` (the weekly
  Calico-for-OpenStack e2e tests), which is new here rather than migrated
  from one of this repo's Semaphore pipelines.

- `config.yaml` + `ciworkflow.yaml` + `modules/*.yaml` — per-PR and per-merge
  repo CI. One workflow composed from modules, so `depends:` and the artifact
  namespace can cross component boundaries.
- `depstree.yaml` — **generated.** What each component's CI must re-run for, as
  path patterns. See below.

These crons and scripts are maintained **by hand** going forward: edit the
YAML (or the scripts) directly to change a suite's jobs, env, or schedule.

## `depstree.yaml` — generated component triggers

Which paths affect which component is derived from the live Go import graph, not
maintained by hand:

```bash
make gen-deps-files      # regenerates deps.txt files and depstree.yaml
```

CI regenerates and diffs it, so a stale copy fails the build rather than
quietly under-firing a gate. It is the same dependency model the SemaphoreCI
`change_in` clauses are built from — one component cannot come to mean two
different things in the two systems — rendered as anchored regexes because that
is what an ArgoCI gate matches with.

Each entry is one component treated as its own primary package. Combining
several over-fires slightly against a job that names a primary plus secondaries,
and never under-fires, so entries can be unioned freely.

Two things it deliberately does not cover:

- **A component that is not a Go package** has no import graph to derive
  (`whisker`, `manifests`, `charts` content, and `lib`/`pkg`, which are separate
  modules excluded from the component list). Those gate on a hand-written
  pattern — as they do on Semaphore, where `20-lib.yml` uses a literal
  `change_in(['/lib/'])` rather than the `CHANGE_IN` macro.
- **A module's own file.** Editing a job definition should re-run what it
  builds, and only the workflow knows which module belongs to which component —
  so keep that pattern in the `includes:` entry.

### Using it from the workflow

`ciworkflow.yaml` declares the table, and each gate names components from it
instead of listing their paths:

```yaml
dependencies: .argoci/depstree.yaml

includes:
  - path: .argoci/modules/api.yaml
    changes:
      dependsOn: [api]
      in:
        - ^\.argoci/modules/api\.yaml$
```

Declared in the workflow rather than in `config.yaml` so that a reader of a gate
can see where its component names come from without opening another file.

Both halves earn their place: `dependsOn` is what the component is built from,
`in:` is what this workflow additionally wants re-run. Each is judged separately
and the results OR-ed, so a component's `exclude` (every generated one drops
`*.md`) can never suppress a hand-written pattern.

Naming a component that is not in the file fails expansion and lists the ones
that are, so a typo cannot become a gate that quietly matches nothing. Check
before pushing with `argoci-expand`, which prints what each name resolved to:

```bash
argoci-expand -changed git:master...HEAD .argoci/ciworkflow.yaml
```

## Layout is flat (no `end-to-end/` subdir)

Unlike `.semaphore/end-to-end/`, e2e lives at the top of `.argoci/`. ArgoCI's
handler separates workflows by **file role**, not directory: scheduled e2e is
`cron/*.yaml`; per-PR/build CI — when the rest of repo CI moves to ArgoCI — is
`ciworkflow.yaml` + `config.yaml`, which coexist here without a subdir. The
handler also reads crons from a fixed `.argoci/cron/` path, so nesting would
require a handler change for no gain. Scope ownership with path-specific
`CODEOWNERS` entries (e.g. `.argoci/cron/`) rather than directories.

## CI-account env must be set here, not left to banzai-core

banzai-core's `Taskvars` defaults point at the **tigera-dev developer** account.
The CI IAM user can't use them, so any variable whose default names an account
resource has to be exported by this prologue — Semaphore did the same in its
own prologue, and a missing one fails at provision time, not at startup:

| Variable | banzai-core default | Needed by CI |
|---|---|---|
| `KOPS_STATE_STORE_NAME` | `kops-tigera-dev` (403) | `kops-tigera-dev-ci` |
| `KOPS_AWS_DNS_ZONE` | `kops.crc.aws.eng.tigera.net` (no zone) | `kops.ci.aws.eng.tigera.net` |
| `OPENSHIFT_BASE_DOMAIN` | `openshift.crc.aws.eng.tigera.net` (no zone) | `openshift.ci.aws.eng.tigera.net` |
| `AZ_PROJECT` (a subscription *name*) | `tigera-dev` | `tigera-dev-ci` |

Semaphore vars deliberately **not** ported, so the next audit doesn't re-add
them: `KOPS_VERSION`/`RKE_VERSION` (banzai-core resolves or pins these, and
Semaphore's GitHub-API lookup is rate-limit-prone); `DOCKER_EE_*` /
`DOCKER_UCP_VERSION` (superseded by banzai-core's newer `MKE_VERSION`);
`AZ_LOCATION`, `ENABLE_ALP` (defaults already match); `NUM_INFRA_NODES`,
`TEST_TYPE`, `GOOGLE_REGION`, `GOOGLE_ZONE` (set per-job by the crons);
`BZ_*`, `BANZAI_CORE_BRANCH`, `SEMAPHORE_*` (Semaphore-runner specific — the
ArgoCI equivalents are `BZ_HOME`/`BZ_LOCAL_DIR`/`BZ_GLOBAL_BIN`).

## Cron naming (branchless)

Cron filenames and their `generateName` carry **no branch** —
`e2e-nftables.yaml`, `generateName: e2e-nftables-`. `cc-argoci-handler`
appends the **deploy branch** to the CronWorkflow's `metadata.name` when it
expands the file:

| Branch the file is on | Deployed CronWorkflow name |
|---|---|
| `master` | `e2e-nftables-master` |
| `release-v3.33` | `e2e-nftables-release-v3-33` (`.` → `-`) |

All crons share the single `argoci` namespace and are applied upsert-by-name,
so the branch qualifier is what stops `master` and a release branch's copy of
the same file from colliding. Deriving the branch at deploy time (not baking it
into the filename) means a file carried onto a release branch by a cut is
correct with no rename. Keep `generateName` branchless — a baked-in branch
would double up (`…-master-master`).
