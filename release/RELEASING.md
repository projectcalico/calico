# Releasing Calico

> **NOTE:** These instructions apply only to this branch.
> For older releases, refer to the instructions in the corresponding `release-vX.Y` branch.

## Table of contents

- [Releasing Calico](#releasing-calico)
  - [Table of contents](#table-of-contents)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Verify the code is ready for release](#2-verify-the-code-is-ready-for-release)
  - [3. Create a release branch](#3-create-a-release-branch)
    - [Setting up the branch](#setting-up-the-branch)
    - [Updating milestones for the new branch](#updating-milestones-for-the-new-branch)
  - [4. Performing a release](#4-performing-a-release)
    - [4.a Prepare the release branch](#4a-prepare-the-release-branch)
    - [4.b Build and publish the repository in Semaphore](#4b-build-and-publish-the-repository-in-semaphore)
    - [4.c Build and publish tigera/operator](#4c-build-and-publish-tigeraoperator)
    - [4.d Publish the release on Github](#4d-publish-the-release-on-github)
    - [4.e Update the docs with the new version](#4e-update-the-docs-with-the-new-version)
  - [5. Post-release](#5-post-release)
    - [Update milestones](#update-milestones)
    - [Post-release verification](#post-release-verification)
    - [Update API repository](#update-api-repository)
- [Release notes](#release-notes)

## 1. Prerequisites

Generally, the release environment is managed through Semaphore and will already meet these requirements.

However, parts of the process will still require that the following requirements must be met.

To publish Calico, you need **the following permissions**:

- Write access to the projectcalico/calico GitHub repository.
  - Generate a GitHub personal access token and export it as `GITHUB_TOKEN` in your environment.
- Push access to the following repositories
  - Calico DockerHub
  - Calico Quay
  - Tigera Quay
  - projectcalico-org GAR
- You must be a member of the Project Calico team on Launchpad, and have uploaded a GPG identity to your account, for which you have the secret key.

## 2. Verify the code is ready for release

To verify that the code and GitHub are in the right state for releasing the chosen version (vX.Y.Z).

1. [Make sure the Milestone is empty](https://github.com/projectcalico/calico/pulls?q=is:open+is:pr+milestone:%22Calico+vX.Y.Z%22) either by merging PRs, or kicking them out of the Milestone.
2. [Make sure that there are no pending cherry-pick PRs](https://github.com/projectcalico/calico/pulls?q=is%3Aopen+is%3Apr+label%3Acherry-pick-candidate+) relevant to the release.
3. [Make sure CI is passing](https://tigera.semaphoreci.com/projects/calico) for the target release branch.
4. Make sure release notes has been drafted and reviewed. See [Release notes](#release-notes) for more information.

Check the status of each of these items daily in the week leading up to the release.

## 3. Create a release branch

When starting development on a new minor release, the first step is to create a release branch.

**For patch releases, this section can be skipped and you can go directly to [Performing a release](#4-performing-a-release)**

### Setting up the branch

Create a new branch off of the latest master and publish it, along with a dev tag for the next release.
The new release branch is typically `release-vX.Y` where `X.Y` is the new minor version and all the files
in the repository are updated to reflect the new version.

  ```sh
  git checkout master && git pull origin master
  ```

  ```sh
  make create-release-branch
  ```

### Updating milestones for the new branch

Once a new branch is cut, we need to ensure a new milestone exists to represent the next release that will be cut from the master branch.

1. Go to the [Calico milestones page](https://github.com/projectcalico/calico/milestones)

1. Create a new release of the form `Calico vX.Y+1.0`. Leave the existing `Calico vX.Y.0` milestone open.

1. Move any open PRs in the `Calico vX.Y.0` milestone into the new milestone `Calico vX.Y+1.0`.

## 4. Performing a release

### 4.a Prepare the release branch

1. Checkout the release branch `release-vX.Y` and pull the latest changes.

   ```sh
   git checkout release-vX.Y && git pull origin release-vX.Y
   ```

1. Run `make release-prep` to create a `build-vX.Y.Z` branch with updated charts, manifests, and release notes.

   ```sh
   make release-prep
   ```

   This creates a `build-vX.Y.Z` branch, updates version references in charts and manifests,
   runs `make generate`, generates release notes, and commits the changes.
   The version is auto-detected from git state.

1. Review the generated release notes in `release-notes/<VERSION>-release-notes.md` for accuracy and format appropriately. Amend the commit if changes are needed.

1. Get the PR reviewed and ensure it passes CI before moving to the next step.

1. If this is the first release from this release branch i.e. `vX.Y.0`, create a new Calico X.Y.x PPA in launchpad

### 4.b Build and publish the repository in Semaphore

To build and publish the release artifacts, find the desired commit [in Semaphore](https://tigera.semaphoreci.com/projects/calico), verify that all tests for that
commit have passed, and press the `Publish official release` manual promotion button.

Wait for this job to complete before moving on to the next step.

### 4.c Build and publish tigera/operator

Follow the tigera/operator release instructions in the Operator version (vA.B.C) corresponding to the release

```txt
https://github.com/tigera/operator/blob/release-vA.B/RELEASING.md
```

### 4.d Publish the release on Github

Go to the [Calico release page](https://github.com/projectcalico/calico/releases) and publish the draft release.

### 4.e Update the docs with the new version

1. Merge the PR branch created in step 4.a - `build-vX.Y.Z` and delete the branch from the repository.

  > [!WARNING]
  > Do not merge using "Squash and merge" as this will lose the version bump commit history.

## 5. Post-release

### Update milestones

1. Go to the [Calico milestones page](https://github.com/projectcalico/calico/milestones)

1. Open a new milestone of the form `Calico vX.Y.Z+1` for the next patch release in the series if it does not yet exist.

1. Close out the milestone for the release that was just published, moving any remaining open issues and PRs to the newly created milestone.

### Post-release verification

1. Using the [post-release task in Semaphore](https://tigera.semaphoreci.com/projects/calico/schedulers/5eedc2d9-fbbb-4595-b7a5-50fac8068cf2/just_run),
  Specify either the tag `vX.Y.Z` or the `build-vX.Y.Z` branch and click "Run".

1. Check the output of the tests - if any test failed, dig in and understand why.

1. Kick off some e2e tests to test the contents of the release.

### Update API repository

The `projectcalico/api` repository needs to be updated to stay in sync with the Calico API.

**First**, ensure that you have [Github CLI tool](https://github.com/cli/cli#installation)

1. Clone the API repository

   ```sh
   git clone git@github.com:projectcalico/api.git
   ```

1. Create or checkout the release branch `release-vX.Y`.

   For a major/minor release:

   ```sh
   git checkout -b release-vX.Y && git push origin release-vX.Y
   ```

   For a patch release:

   ```sh
   git checkout release-vX.Y && git pull origin release-vX.Y
   ```

1. Update APIs by running the following command

   ```sh
   make -f Makefile.local pr CALICO_GIT_REF=vX.Y.Z`
   ```

   This runs a script that clones `projectcalico/calico`, import the updated files and creates a PR.

   > NOTE: if an auto-api PR already exists for this version,
   > it will print an error about the PR existing already.
   > The existing PR still gets updated with changes

1. Get the PR reviewed, approved and merged

# Release notes

Release notes for a Calico release contain notable changes across Calico repositories. To write release notes for a given version, perform the following steps.

1. Check the merged pull requests in the milestone and make sure each has a release note if it needs one.

   Use this URL to query for PRs, replacing `vX.Y.Z` with your desired version.

   ```sh
   https://github.com/issues?utf8=%E2%9C%93&q=user%3Aprojectcalico+milestone%3A%22Calico+vX.Y.Z%22+
   ```

   Each PR that wants a release note must meet the following conditions to have its release note considered:

   - It is in the correct `Calico vX.Y.Z` GitHub milestone
   - It has the `release-note-required` label
   - It has one or more release notes included in the description.

2. Run the following command to collect all release notes for the given version.

   ```sh
   make release-notes
   ```

   A file called `release-notes/<VERSION>-release-notes.md` will be created with the raw release note content.

3. Edit the generated file.

   The release notes should be edited to highlight a few major enhancements and their value to the user. Bug fixes and other changes should be summarized in a bulleted list at the end of the release notes. Any breaking changes, limitations or incompatible changes in behavior should be explicitly noted.

   Consistent release note formatting is important. Here are some examples for reference:

   - [Example release notes for a major/minor release](https://github.com/projectcalico/calico/blob/release-v3.30/release-notes/v3.30.0-release-notes.md)
   - [Example release notes for a patch release](https://github.com/projectcalico/calico/blob/release-v3.30/release-notes/v3.30.4-release-notes.md)

4. Add the generated file to git.

   ```sh
   git add release-notes/
   ```
