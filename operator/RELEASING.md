# Releasing the operator

## Preparing a new release branch

For a major or minor release, you will need to create a new `release-vX.Y` branch, a dev tag on master,
and a GitHub milestone for the next release. The `create-release-branch` Makefile target automates creating
the branch and dev tag; you will create the milestone manually in a later step:

```sh
make create-release-branch RELEASE_STREAM=vX.Y CALICO_REF=<calico-git-ref> ENTERPRISE_REF=<enterprise-git-ref>
```

This command:

- Creates a `release-vX.Y` branch from master
- Updates `config/calico_versions.yml` and `config/enterprise_versions.yml` to point at the given refs
- Updates `VERSION_TAG` in `Makefile` to match the Calico version
- Runs `make fix gen-versions-calico gen-versions-enterprise` to regenerate files
- Commits the changes to the release branch
- Switches back to master, creates an empty commit, and tags it `vX.(Y+1).0-0.dev`
- Pushes the release branch, master, and tag to the remote

**Flags / environment variables:**

| Env var                                | Flag               | Description                                                       |
| -------------------------------------- | ------------------ | ----------------------------------------------------------------- |
| `STREAM` / `RELEASE_STREAM` (required) | `--stream`         | Release stream, e.g., `v1.43`                                     |
| `CALICO_REF` (required)                | `--calico-ref`     | Calico git ref (branch or tag), e.g., `release-v3.32`             |
| `ENTERPRISE_REF` (required)            | `--enterprise-ref` | Enterprise git ref (branch or tag), e.g., `release-calient-v3.22` |

After the branch is created, create the next minor release's first milestone at
https://github.com/tigera/operator/milestones (e.g., if `release-v1.43` was created,
create milestone `v1.44.0`).

### Validating the branch cut

Once the release branch, dev tag, and next-version milestone are in place, run:

```sh
make branch-validate RELEASE_STREAM=vX.Y
```

This runs a suite of checks against the remote state to catch common branch-cut mistakes:

- The `release-vX.Y` branch exists in the operator remote
- The Calico branch referenced in `config/calico_versions.yml` exists in `projectcalico/calico`
- `VERSION_TAG` in the release branch's `Makefile` matches the Calico version in `config/calico_versions.yml`
- The Enterprise branch referenced in `config/enterprise_versions.yml` exists in `tigera/calico-private`
- The next dev tag (`vX.(Y+1).0-0.dev`) exists on the operator remote
- The next minor release's milestone (`vX.(Y+1).0`) exists and is open

Use `GIT_REMOTE=<remote>` to target a different remote (default: `origin`). Any failure is reported per check;
fix the offending state and re-run.

## Preparing for the release

Checkout the release branch from which you want to release. Ensure that you are using the correct
operator version for the version of Calico or Enterprise that you are releasing. If in doubt,
check [the releases page](https://github.com/tigera/operator/releases) to find the most
recent Operator release for your Calico or Enterprise minor version.

Run the following command:

```sh
make release-prep VERSION=<OPERATOR_VERSION> [CALICO_VERSION=<CALICO_VERSION>] [ENTERPRISE_VERSION=<ENTERPRISE_VERSION>]
```

At least one of `CALICO_VERSION` or `ENTERPRISE_VERSION` must be provided. The versions must
exist as tags in their respective GitHub repositories.

This command:

- Validates that the current branch is a release branch (e.g. `release-v1.43`)
- Validates that the provided Calico/Enterprise versions exist as tags in their remote repositories
- Updates `config/calico_versions.yml` and/or `config/enterprise_versions.yml` with the specified versions
- Updates the Enterprise registry if needed
- Runs `make fix gen-versions` to regenerate component files
- Commits the changes to a new `build-<VERSION>` branch
- Pushes the branch and creates a PR against the release branch
- Manages GitHub milestones for the release stream (creates next patch milestone, closes current)

**Flags / environment variables:**

| Env var               | Flag                    | Description                                                   |
| --------------------- | ----------------------- | ------------------------------------------------------------- |
| `VERSION` (required)  | `--version`             | Operator version to release, e.g., `v1.43.2`                  |
| `CALICO_VERSION`      | `--calico-version`      | Calico version tag, e.g., `v3.30.2`                           |
| `ENTERPRISE_VERSION`  | `--enterprise-version`  | Enterprise version tag, e.g., `v3.22.0-1.0`                   |
| `ENTERPRISE_REGISTRY` | `--enterprise-registry` | Override Enterprise image registry                            |
| `CALICO_DIR`          | `--calico-dir`          | Local Calico CRDs directory (skips remote ref validation)     |
| `ENTERPRISE_DIR`      | `--enterprise-dir`      | Local Enterprise CRDs directory (skips remote ref validation) |

Once the PR is created, get it reviewed and merged.

## Releasing

Once the PR from [the previous step](#preparing-for-the-release) is merged, follow these steps to create the release:

1. Merge your PR to the release branch

1. Create a git tag `<tag>` for the new commit on the release branch and push it:

    ```sh
    git tag <tag> # e.g git tag v1.30.2
    git push <remote> <tag> # e.g git push origin v1.30.2
    ```

  Pushing the tag should automatically run the release pipeline in CI.

1. Once the CI run is done, go to [releases](https://github.com/tigera/operator/releases) and edit the draft release *as needed* before publishing it.

  > [!IMPORTANT]
  > Only mark this release as latest if it is the highest released version

## Updates for new Calico CRDs

(TODO: We need to be able to detect new CRDs and do this automatically)

If the release includes new Calico CRDs, add the new CRDs to `hack/gen-bundle/get-manifests.sh` and `config/manifests/bases/tigera-operator.clusterserviceversion.yaml`.
