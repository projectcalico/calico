# End-to-end CI scripts

Orchestrator scripts for the Semaphore e2e jobs. Two top-level entry points
drive two different job shapes:

| Entry point | Job shape |
|---|---|
| `body_standard.sh` | Standard e2e: provision a cluster, install Calico, optionally migrate/upgrade, run tests |
| `body_flannel-migration.sh` | Flannel-to-Calico migration test with a pre- and post-migration test run |

Both dispatch to single-purpose **phase scripts** under `phases/`. Each phase
is self-contained, documents its required env vars at the top, and can be
sourced individually when reproducing part of a CI run locally.

## Phases

| Phase | Purpose |
|---|---|
| `phases/provision.sh` | `bz provision` + Semaphore cache store |
| `phases/install.sh` | `bz install` (install Calico on the provisioned cluster) |
| `phases/configure.sh` | Post-install env setup: PATH, external-node creds, IPAM pool, failsafe ports |
| `phases/migrate.sh` | Optional operator migration, AKS migration, `bz upgrade` |
| `phases/run_tests_local.sh` | Build and run the in-repo e2e binary via `make e2e-run` (wrapped in calico/go-build) |
| `phases/hcp.sh` | Hosted control plane flow (separate provision + test tooling) |

## Reproducing a CI run locally

Each phase script lists its required env vars in its header comment. In the
common case, reproducing a CI job looks like:

```bash
cd "${BZ_HOME}"
source phases/provision.sh
source phases/install.sh
source phases/configure.sh
source phases/run_tests_local.sh
```

Phases are **sourced**, not executed, so env vars exported by earlier phases
(e.g. `PATH`, `EXT_IP`) flow into later phases. Running a phase standalone
works the same way -- source it from a shell you've set up with the
required env vars.

## Adding a new phase

1. Create `phases/<name>.sh` with a header comment listing required env vars.
2. Omit `set -eo pipefail` from the phase -- the orchestrator sets it once
   and phases inherit via sourcing.
3. Add the phase to the appropriate body script's dispatch logic.
4. Add a row to the phase table above.

## The in-repo test runner

`phases/run_tests_local.sh` invokes `make e2e-run` at the repository root.
That Makefile target is the single canonical entry point for running the
in-repo e2e binary -- the same target kind-based CI (`20-e2e.yml`) uses via
`make e2e-test`, and the same target developers can use against any cluster:

```bash
KUBECONFIG=/path/to/kubeconfig \
  E2E_TEST_CONFIG=e2e/config/gcp-bpf.yaml \
  make e2e-run
```

See `e2e/config/*.yaml` for available test-selection configs and
`e2e/pkg/testconfig/` for the config format.

## Legacy notes

- The `docker run calico/go-build ...` wrapper around `make e2e-run` in
  `run_tests_local.sh` is legacy. Once the in-repo binary reaches parity
  with the enterprise test suite, the wrapper should be removed and the
  script should call `make e2e-run` directly.
- `body_flannel-migration.sh` still uses `./bz.sh tests:run` for its pre-
  and post-migration test runs -- that's a different legacy runner than
  `bz tests` and has tests the in-repo binary doesn't yet cover. Migrate
  to `make e2e-run` when parity lands.
