# Releasing the operator

## Preparing a new release branch

For a major or minor release, you will need to create a new `release-vX.Y` branch, a dev tag on master,
and a GitHub milestone for the next release. The `create-release-branch` Makefile target automates creating
the branch and dev tag; you will create the milestone manually in a later step:

```sh
make create-release-branch RELEASE_STREAM=vX.Y
```

This command:

- Creates a `release-vX.Y` branch from master
- Switches back to master, creates an empty commit, and tags it `vX.(Y+1).0-0.dev`
- Pushes the release branch, master, and tag to the remote

The branch needs no version pinning: the operator resolves the Calico version it deploys
from the build, so a release branch builds at the Calico version it was cut from.

**Flags / environment variables:**

| Env var                                | Flag               | Description                                                       |
| -------------------------------------- | ------------------ | ----------------------------------------------------------------- |
| `STREAM` / `RELEASE_STREAM` (required) | `--stream`         | Release stream, e.g., `v1.43`                                     |

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
- The next dev tag (`vX.(Y+1).0-0.dev`) exists on the operator remote
- The next minor release's milestone (`vX.(Y+1).0`) exists and is open

Use `GIT_REMOTE=<remote>` to target a different remote (default: `origin`). Any failure is reported per check;
fix the offending state and re-run.

## Preparing for the release

Checkout the release branch from which you want to release. Ensure that you are using the correct
operator version for the version of Calico that you are releasing. If in doubt,
check [the releases page](https://github.com/tigera/operator/releases) to find the most
recent Operator release for your Calico minor version.

Run the following command:

```sh
make release-prep VERSION=<OPERATOR_VERSION>
```

This command:

- Validates that the current branch is a release branch (e.g. `release-v1.43`)
- Creates a `build-<VERSION>` branch, committing any generated-file changes it finds
- Pushes the branch and creates a PR against the release branch
- Manages GitHub milestones for the release stream (creates next patch milestone, closes current)

**Flags / environment variables:**

| Env var               | Flag                    | Description                                                   |
| --------------------- | ----------------------- | ------------------------------------------------------------- |
| `VERSION` (required) | `--version`        | Operator version to release, e.g., `v1.43.2` |

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
