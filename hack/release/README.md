# release

`release` is a tool designed to streamline the process of creating and releasing a new operator.

- [release](#release)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Build and publish a release](#build-and-publish-a-release)
    - [Build and publish a hashrelease](#build-and-publish-a-hashrelease)
  - [Commands](#commands)
    - [release branch](#release-branch)
      - [Examples](#examples)
    - [release build](#release-build)
      - [Examples](#examples-1)
    - [release publish](#release-publish)
      - [Examples](#examples-2)
    - [release prep](#release-prep)
      - [Examples](#examples-3)
    - [release notes](#release-notes)
      - [Examples](#examples-4)
    - [release github](#release-github)
      - [Examples](#examples-5)
    - [release from](#release-from)
      - [Examples](#examples-6)

## Installation

To install:

```bash
make hack/bin/release
```

  > [!TIP]
  > Add `hack/bin` to your `PATH` to allow running the tool using `release` command.

## Usage

To start, familiarize yourself with the tool

```sh
release --help
```

For more information on a specific command, see [Commands](#commands) section or use:

```sh
release <command> --help
```

### Build and publish a release

To build and publish a vA.B.C release, it use the `release build` and `release publish` commands.
For more information, see [release build](#release-build) and [release publish](#release-publish) sections.

Below will use the makefile target to demonstrate the usage (as expected to be run from the root of the repository).

> ![WARNING]
> This assumes user has made all the necessary changes to [prepare for the release](../RELEASING.md#preparing-for-the-release).

1. Build the operator image for version `vA.B.C`

   ```sh
   make release VERSION=vA.B.C
   ```

1. Publish the operator image to the container registry and create GitHub release.
By default, it creates a draft release.

   1. Create GitHub release as draft

     ```sh
     make release-publish VERSION=vA.B.C
     ```

     To make the draft GitHub release public, either go to the [Releases](https://github.com/tigera/operator/releases) page and publish the draft release or run locally:

     ```sh
     make release-github VERSION=vA.B.C
     ```

     This uses the `release github` command under the hood. See [release github](#release-github) section for more information.

   1. Create GitHub release and make it public directly

     ```sh
     make release-publish VERSION=vA.B.C DRAFT_GITHUB_RELEASE=false
     ```

### Calico Cloud variant

Run any release target with `VARIANT=cloud` to build the Calico Cloud operator instead of the
enterprise one, e.g. `make release-tag VARIANT=cloud RELEASE_TAG=vA.B.C-cloud`. It is the same
binary and the same targets — only a few defaults change (publish to `gcr.io/tigera-tesla/operator-cloud`,
a `-cloud`-suffixed version, no GitHub release). Those variant-dependent defaults are resolved at
startup in `internal/setup`; see that package's doc comment for how and why.

In CI this runs automatically off the same tag as enterprise: pushing a `vA.B.C` release tag builds
both the enterprise image and, from the same commit with `VARIANT=cloud`, the `vA.B.C-cloud` image —
they are parallel jobs in the same `Release` block (see `.semaphore/release.yml`). There are no
separate cloud release tags or pipelines.

### Build and publish a hashrelease

This is similar to [building and publishing a release](#build-and-publish-a-release), it uses the `release build` and `release publish` commands.
However, some additonal flags are used to provide more information on the Calico or Calico Enterprise version to be included in the hashrelease.
Unlike a release, a hashrelease is typically for either a Calico or Calico Enterprise version not both *though it is possible to do both but not advised*.

1. Given an operator development version `vA.B.C-0.dev-N-gHAAAAAAAAASH`

   1. Build the hashrelease operator image for Calico vX.Y.Z-0.dev-N-gSHAAAAAAAAAA

      ```sh
      make release HASHRELEASE=true VERSION=vA.B.C-0.dev-XXX-gYYYYYYYYYYYY-vX.Y.Z-0.dev-N-gSHAAAAAAAAAA \
        --calico-version vX.Y.Z-0.dev-N-gSHAAAAAAAAAA --calico-dir path/to/local/calico-repo

      # alternatively, using versions file
      # make release HASHRELEASE=true VERSION=vA.B.C-0.dev-XXX-gYYYYYYYYYYYY-vX.Y.Z-0.dev-N-gSHAAAAAAAAAA \
      #   --calico-versions path/to/calico-versions.yaml
      ```

   1. Build the hashrelease operator image for Calico Enterprise vX.Y.Z-calient-0.dev-N-gSHAAAAAAAAAA

      ```sh
      make release HASHRELEASE=true VERSION=vA.B.C-0.dev-XXX-gYYYYYYYYYYYY-vX.Y.Z-calient-0.dev-N-gSHAAAAAAAAAA \
        --enterprise-version vX.Y.Z-calient-0.dev-N-gSHAAAAAAAAAA --enterprise-dir path/to/local/enterprise-repo

      # alternatively, using versions file
      # make release HASHRELEASE=true VERSION=vA.B.C-0.dev-XXX-gYYYYYYYYYYYY-vX.Y.Z-calient-0.dev-N-gSHAAAAAAAAAA \
      #   --enterprise-versions path/to/enterprise-versions.yaml
      ```

1. Publish the hashrelease operator image to the container registry.

   1. For Calico hashrelease

     ```sh
     make release-publish HASHRELEASE=true VERSION=vA.B.C-0.dev-XXX-gYYYYYYYYYYYY-vX.Y.Z-0.dev-N-gSHAAAAAAAAAA
     ```

   1. For Calico Enterprise hashrelease

     ```sh
     make release-publish HASHRELEASE=true VERSION=vA.B.C-0.dev-XXX-gYYYYYYYYYYYY-vX.Y.Z-calient-0.dev-N-gSHAAAAAAAAAA
     ```

## Commands

### release branch

This command creates a new release branch for the operator.
It updates the calico and enterprise version configs on the release branch, regenerates files,
and commits the changes. It then switches back to master, creates an empty commit tagged
with `vX.Y.0-0.dev` (so that `git describe --tags` produces sensible versions for subsequent
master commits), and pushes the release branch, master, and tag to the remote.

Both `--calico-ref` and `--enterprise-ref` are required.
They specify the git ref (branch or tag) to use for each product's version config.

```sh
release branch --stream <vX.Y> --calico-ref <git-ref> --enterprise-ref <git-ref>
```

If the `--local` flag is specified, the branch and tag are created locally without pushing to the remote.

| Flag                      | Env var                    | Description                                   |
| ------------------------- | -------------------------- | --------------------------------------------- |
| `--stream`                | `RELEASE_STREAM`/ `STREAM` | Release stream (e.g., `v1.43`). Required.     |
| `--calico-ref`            | `CALICO_REF`               | Calico git ref (branch or tag). Required.     |
| `--enterprise-ref`        | `ENTERPRISE_REF`           | Enterprise git ref (branch or tag). Required. |
| `--release-branch-prefix` | `RELEASE_BRANCH_PREFIX`    | Branch name prefix (default: `release`).      |
| `--local`                 | `LOCAL`                    | Skip pushing to remote.                       |

There is also a Makefile target:

```sh
make create-release-branch RELEASE_STREAM=vX.Y CALICO_REF=<ref> ENTERPRISE_REF=<ref>
```

#### Examples

1. To create a release branch for operator v1.42 with Calico v3.32 and Enterprise v3.22

    ```sh
    release branch --stream v1.42 --calico-ref release-v3.32 --enterprise-ref release-calient-v3.22
    ```

1. To perform the same action as above but only locally without pushing to the remote

    ```sh
    release branch --stream v1.42 --calico-ref release-v3.32 --enterprise-ref release-calient-v3.22 --local
    ```

### release build

This command builds the operator image for a specific operator version.

To build the operator image, use the following command:

```sh
release build --version <operator version>
```

For hashrelease, use the `--hashrelease` flag and provide either the Calico or Calico Enterprise version or versions file.
When using Calico or/and Calico Enterprise version, the local directory of the respective repository must be provided.
When using versions file, provide the path to the local director of the respective repository if local changes are to be included;
otherwise, the latest commit for the respective

```sh
release build --version <operator version> --hashrelease \
  [--calico-version <calico version> | --calico-versions <path to calico version file> |--enterprise-version <enterprise version> | --enterprise-versions <path to enterprise version file>] [--calico-dir <path to local calico repo> | --enterprise-dir <path to local enterprise repo>]
```

#### Examples

1. To build the operator image for operator version `v1.36.0`

    ```sh
    release build --version v1.36.0
    ```

1. To build hashrelease operator image for Calico v3.30

   1. Using Calico versions file

         ```sh
         release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 \
          --calico-versions path/to/calico-versions.yaml
         ```

   1. Specifying version directly

       ```sh
       release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 \
        --calico-version v3.30.0-0.dev-338-gca80474016a5 --calico-dir path/to/local/calico-repo
       ```

1. To build hashrelease operator image for Calico Enterprise v3.22

   1. Using Enterprise versions file

         ```sh
         release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.22.0-calient-0.dev-100-gabcdef123456 \
          --enterprise-versions path/to/enterprise-versions.yaml
         ```

   1. Specifying version directly

       ```sh
       release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.22.0-calient-0.dev-100-gabcdef123456 \
        --enterprise-version v3.22.0-calient-0.dev-100-gabcdef123456 --enterprise-dir path/to/local/enterprise-repo
       ```

1. *Not typically recommended*, but to build hashrelease operator image for both Calico v3.30 and Calico Enterprise v3.22

   1. Using versions file

         ```sh
         release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5-v3.22.0-calient-0.dev-100-gabcdef123456 \
          --calico-versions path/to/calico-versions.yaml --enterprise-versions path/to/enterprise-versions.yaml
         ```

   1. Specifying versions directly

       ```sh
       release build --hashrelease --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5-v3.22.0-calient-0.dev-100-gabcdef123456 \
        --calico-version v3.30.0-0.dev-338-gca80474016a5 --calico-dir path/to/local/calico-repo \
        --enterprise-version v3.22.0-calient-0.dev-100-gabcdef123456 --enterprise-dir path/to/local/enterprise-repo
       ```

### release publish

This commands publishes the operator image for a specific operator version to a container registry.

```sh
release publish --version <operator version>
```

For hashrelease, use the `--hashrelease` flag

```sh
release publish --version <operator version> --hashrelease
```

If this is a release version (i.e. vX.Y.Z) and the `--create-github-release` flag is set to true,
it creates a draft release on the [Releases](https://github.com/tigera/operator/releases) page.

#### Examples

1. To publish the operator version `v1.36.0`

    ```sh
    release publish --version v1.36.0
    ```

1. To publish the hashrelease operator image for operator v1.36 with Calico v3.30

    ```sh
    release publish --version v1.36.0-0.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --hashrelease
    ```

1. To publish the operator version `v1.36.0` and create a GitHub release

    ```sh
    release publish --version v1.36.0 --create-github-release
    ```

### release prep

This command prepares the repo for a new release.
This typically involves updating the versions config files, image registry for the product if applicable,
and re-generating any generated files.
All the changes are committed to a new branch, which is then pushed to the remote
and a pull request is created against the release branch for review.
Finally, it manages the milestones on GitHub for the release stream associated with the new release,
which involves creating a new milestone for the next patch version and closing the current milestone
for the release version. All open issues and pull requests associated with the current milestone
are moved to the new milestone.

  > [!IMPORTANT]
  > At least one of Calico or Calico Enterprise version must be specified.
  > If both are specified, the versions files for both products are updated.

To prepare for a new release, use the following command:

```sh
release prep --version <new operator version> [--calico-version <calico version> |
--enterprise-version <calico enterprise version>]
```

If the `--local` flag is specified, none of the remote changes will be made i.e.
no branch in the remote repo and no pull request will be created. Also milestones will not be modified on GitHub.

#### Examples

1. To prepare for a new release `v1.36.0` with Calico version `v3.30.0`

    ```sh
    release prep --version v1.36.0 --calico-version v3.30.0
    ```

1. To prepare for a new release `v1.36.0` with Calico Enterprise version `v3.20.0-1.0`

    ```sh
    release prep --version v1.36.0 --enterprise-version v3.20.0-1.0
    ```

1. To prepare for a new release `v1.36.0` with Calico version `v3.30.0`
   and Calico Enterprise version `v3.20.0-1.0` using local changes only

    ```sh
    release prep --version v1.36.0 --calico-version v3.30.0 --enterprise-version v3.20.0-1.0 --local
    ```

### release notes

This command generates release notes for a specific operator version.
To generate release notes, use the following command:

```sh
release notes --version <operator version>
```

The generated releases notes are saved in a markdown file named `<operator version>-release-notes.md`.

The release notes includes the Calico and Calico Enterprise versions included in the operator version.
By default, this is gotten from the versions files corresponding to the product in `config/` directory
in the commit with the tag matching the operator version.

To get the versions file from the local working directory instead of the tagged commit, use the `--local` flag.

#### Examples

1. To generate release notes for operator version `v1.36.0` from the tagged commit

    ```sh
    release notes --version v1.36.0
    ```

1. To generate release notes for operator version `v1.36.0` using the local versions files

    ```sh
    release notes --version v1.36.0 --local
    ```

### release github

This command creates or updates a GitHub release for a specific operator version.
To create or update a GitHub release, use the following command:

```sh
release github --version <operator version>
```

By default, the GitHub release is not created in draft mode. To create a draft release, use the `--draft` flag.

#### Examples

1. To create or update a GitHub release for operator version `v1.36.0`

    ```sh
    release github --version v1.36.0
    ```

1. To create or update a draft GitHub release for operator version `v1.36.0`

    ```sh
    release github --version v1.36.0 --draft
    ```

### release from

This command creates a new operator version based on a previous operator version.
The base operator version must reference either a tag or commit hash in `tigera/operator`.
The new operator version will be built from the current codebase
with updates made to the image list based on the changes passed in.

```sh
release from --base-version <previous operator version> --version <version to release> \
  [--except-calico | --except-calico-enterprise] <image>:<image version>
```

> [!IMPORTANT]
> To publish the newly created operator, use the `--publish` flag
>
> `--publish` will push the operator image to remote repository
> and ONLY create a draft release on the [Releases](https://github.com/tigera/operator/releases) page for release versions (i.e. vX.Y.Z)

#### Examples

1. To create a new operator with an updated `typha` for Calico to a custom registry locally

    ```sh
    release from --base-version v1.36.0-1.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --version v1.36.0-mod-typha \
    --except-calico typha:v3.30.0-0.dev-353-ge0bc56c0d646 --registry quay.io --image my-namespace/tigera-operator
    ```

1. To create a new operator with an updated `typha` for Calico to a custom registry

    ```sh
    release from --base-version v1.36.0-1.dev-259-g25c811f78fbd-v3.30.0-0.dev-338-gca80474016a5 --version v1.36.0-mod-typha \
    --except-calico typha:v3.30.0-0.dev-353-ge0bc56c0d646 --registry quay.io --image my-namespace/tigera-operator --publish
    ```

1. To create a new operator release `v1.36.3` that has almost all the same images as `v1.36.2`
    with the exception of Enterprise `linseed` component using `v3.20.0-2.2` locally.

    > [!WARNING]
    > This assumes that user has push access to [`tigera/operator`](https://github.com/tigera/operator)

    ```sh
    release from --base-version v1.36.2 --version v1.36.3 \
      --except-calico-enterprise linseed:v3.20.0-2.2
    ```

1. To create a new operator release `v1.36.3` that has almost all the same images as `v1.36.2`
    with the exception of Enterprise `linseed` component using `v3.20.0-2.2`.

    > [!WARNING]
    > This assumes that user has push access to [`tigera/operator`](https://github.com/tigera/operator)
    > and [`quay.io/tigera/operator`](https://quay.io/repository/tigera/operator)

    ```sh
    release from --base-version v1.36.2 --version v1.36.3 \
      --except-calico-enterprise linseed:v3.20.0-2.2 --publish
    ```
