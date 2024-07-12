# How to release Calico

> **NOTE:** These instructions apply only to Calico versions v3.21 or greater.
> For older releases, refer to the instructions in the corresponding `release-vX.Y` branch.

## Table of contents

1. [Prerequisites](#1-prerequisites)
1. [Verify the code is ready for release](#2-verify-the-code-is-ready-for-release)
1. [Create a release branch](#3-create-a-release-branch)
1. [Performing a release](#4-performing-a-release)
1. [Promoting to be the latest release in the docs](#5-promoting-to-be-the-latest-release-in-the-docs)
1. [Post-release](#6-post-release)

## 1. Prerequisites

Generally, the release environment is managed through Semaphore and will already meet these requirements. However, if you must run
the process locally then the following requirements must be met.

To publish Calico, you need **the following permissions**:

- Write access to the projectcalico/calico GitHub repository. You can create a [personal access token](https://github.com/settings/tokens) for GitHub and export it as the `GITHUB_TOKEN` env var (for example by adding it to your `.profile`).

- Push access to the Calico DockerHub repositories. Assuming you've been granted access by an admin:

    ```
    docker login
    ```

- Push access to the Calico quay.io repositories. Assuming you've been granted access by an admin:

    ```
    docker login quay.io
    ```

- Push access to the gcr.io/projectcalico-org repositories. **Note:** Some of the repos do not yet support credential helpers, you must use one of the token-based logins.  For example, assuming you've been granted access, this will configure a short-lived auth token:

    ```
    gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin https://gcr.io
    ```

- You must be a member of the Project Calico team on Launchpad, and have uploaded a GPG identity to your account, for which you have the secret key.

- You must be able to access binaries.projectcalico.org.

- To publish the helm release to the repo, you’ll need an AWS helm profile:
  Add this to your ~/.aws/config
      ```
      [profile helm]
      role_arn = arn:aws:iam::<production_account_id>:role/CalicoDevHelmAdmin
      mfa_serial = arn:aws:iam::<tigera-dev_account_id>:mfa/myusername
      source_profile = default
      region = us-east-2
      ```
  Your user will need permission for assuming the helm admin role in the production account.

You'll also need **several GB of disk space**.

Some of the release scripts also require **tools to be installed** in your dev environment:

- [Install and configure](https://github.com/github/hub#installation) the GitHub `hub` tool.

Finally, the release process **assumes that your repos are checked out with name `origin`** for the git remote
for the main Calico repo.

## 2. Verify the code is ready for release

To verify that the code and GitHub are in the right state for releasing the chosen version.

1. [Make sure the Milestone is empty](https://github.com/projectcalico/calico/pulls?q=is%3Aopen+is%3Apr+milestone%3A%22Calico+v3.21.3%22) either by merging PRs, or kicking them out of the Milestone.
1. [Make sure that there are no pending cherry-pick PRs](https://github.com/projectcalico/calico/pulls?q=is%3Aopen+is%3Apr+label%3Acherry-pick-candidate+) relevant to the release.
1. [Make sure there are no pending PRs which need docs](https://github.com/projectcalico/calico/pulls?q=is%3Apr+label%3Adocs-pr-required+is%3Aclosed+milestone%3A%22Calico+v3.21.3%22) for this release.
1. [Make sure each PR with a release note is within a Milestone](https://github.com/projectcalico/calico/pulls?q=is%3Apr+label%3Arelease-note-required+is%3Aclosed+milestone%3A%22Calico+v3.21.3%22+).
1. [Make sure CI is passing](https://tigera.semaphoreci.com/projects/calico) for the target release branch.

Check the status of each of these items daily in the week leading up to the release.

## 3. Create a release branch

When starting development on a new minor release, the first step is to create a release branch.

**For patch releases, this section can be skipped and you can go directly to [Performing a release](#4-performing-a-release)**

### Setting up the branch

1. Create a new branch off of the latest master and publish it, along with a dev tag for the next release.

   ```
   git checkout master && git pull origin master
   ```

   ```
   make create-release-branch
   ```

1. Checkout the newly created branch.

   ```
   git checkout release-vX.Y
   ```

1. Update manifests to use the new release branch instead of master.  Update versions in the following files:

   - charts/calico/values.yaml
   - charts/tigera-operator/values.yaml

   Then, run manifest generation

   ```
   make generate
   ```

   Commit your changes

   ```
   Update manifests for release-vX.Y
   ```

   Then, push your changes to the branch.

   ```
   git push origin release-vX.Y
   ```

### Setting up netlify

1. On netlify create a new site using the `release-vX.Y` branch (You should at least have write access to this repo for site creation)

1. Rename the randomly generated site name to follow the same naming convention as other releases (Ex: `calico-vX-Y`).

1. Ensure that the site is generated properly by visiting site URL (Ex. https://calico-vX-Y.netlify.app/archive/vX.Y/).

1. Cherry-pick the proxy rules commit created earlier to the latest production branch, as well as `master`.
   This will make the candidate site docs available at `projectcalico.docs.tigera.io/archive/vX.Y/` (Note: the trailing slash)

### Updating milestones for the new branch

Once a new branch is cut, we need to ensure a new milestone exists to represent the next release that will be cut from the master branch.

1. Go to the [Calico milestones page](https://github.com/projectcalico/calico/milestones)

1. Create a new release of the form `Calico vX.Y+1.0`. Leave the existing `Calico vX.Y.0` milestone open.

## 4. Performing a release

### 4.a Create a temporary branch for this release against origin

1. Create a new branch based off of `release-vX.Y`.

   ```
   git checkout release-vX.Y && git pull origin release-vX.Y
   ```

   ```
   git checkout -b build-vX.Y.Z
   ```

1. Update version information in the following files:

   - `charts/calico/values.yaml`: Calico version used in manifest generation.
   - `charts/tigera-operator/values.yaml`: Versions of operator and calicoctl used in the helm chart and manifests.

1. Update manifests (and other auto-generated code) by running the following command in the repository root.

   ```
   make generate
   ```

1. Follow the steps in [writing release notes](#release-notes) to generate candidate release notes.

   Then, add the newly created release note file to git.

   ```
   git add release-notes/<VERSION>-release-notes.md
   ```

1. Commit your changes. For example:

   ```
   git commit -m "Updates for vX.Y.Z"
   ```

1. Push the branch to `github.com/projectcalico/calico` and create a pull request. Get it reviewed and ensure it passes CI before moving to the next step.

### 4.b Build and publish the repository in Semaphore

To build and publish the release artifacts, find the desired commit [in Semaphore](https://tigera.semaphoreci.com/projects/calico), verify that all tests for that
commit have passed, and press the `Publish official release` manual promotion button.

Wait for this job to complete before moving on to the next step.

### 4.c Build and publish tigera/operator

Follow [the tigera/operator release instructions](https://github.com/tigera/operator/blob/master/RELEASING.md).

### 4.d Build and publish OpenStack packages

1. Check out the release tag in the `projectcalico/calico` repository.

   ```
   git fetch origin --tags && git checkout vX.Y.Z
   ```

1. In your environment, set `HOST` to the GCP name for binaries.projectcalico.org, `GCLOUD_ARGS` to the `--zone` and `--project` args needed to access that host, and `SECRET_KEY` to
   the secret key for a GPG identity that you have uploaded to your Launchpad account.

1. Establish GCP credentials so that gcloud with `HOST` and `GCLOUD_ARGS` can access binaries.projectcalico.org.

1. Build OpenStack packages from the checked out commit.

   ```
   make -C hack/release/packaging release-publish VERSION=vX.Y.Z
   ```

### 4.e Update the docs with the new version

1. Merge the PR branch created in step 4.a - `build-vX.Y.Z` and delete the branch from the repository.

## 5. Post-release

### Update milestones

1. Go to the [Calico milestones page](https://github.com/projectcalico/calico/milestones)

1. Open a new milestone of the form `Calico vX.Y.Z` for the next patch release in the series if it does not yet exist.

1. Close out the milestone for the release that was just published, moving any remaining open issues and PRs to the newly created milestone.

### Post-release verification

1. Run the post-release checks. The release validation checks will run - they check for the presence of all the required binaries tarballs, tags, etc.
   
   ```
   make VERSION=... FLANNEL_VERSION=... OPERATOR_VERSION=... postrelease-checks
   ```   

1. Check the output of the tests - if any test failed, dig in and understand why.

1. Kick off some e2e tests to test the contents of the release.

# Release notes

Release notes for a Calico release contain notable changes across Calico repositories. To write release notes for a given version, perform the following steps.

1. Check the merged pull requests in the milestone and make sure each has a release note if it needs one.

   Use this URL to query for PRs, replacing `vX.Y.Z` with your desired version.

   ```
   https://github.com/issues?utf8=%E2%9C%93&q=user%3Aprojectcalico+milestone%3A%22Calico+vX.Y.Z%22+
   ```

   Each PR that wants a release note must meet the following conditions to have its release note considered:

   - It is in the correct `Calico vX.Y.Z` GitHub milestone
   - It has the `release-note-required` label
   - It has one or more release notes included in the description (Optional).

1. Run the following command to collect all release notes for the given version.

   ```
   make release-notes
   ```

   A file called `release-notes/<VERSION>-release-notes.md` will be created with the raw release note content.

   > **NOTE**: If you receive a ratelimit error, you can specify a `GITHUB_TOKEN` in the above command to
   > increase the number of allowed API calls. [See here for details](https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/).

1. Edit the generated file.

   The release notes should be edited to highlight a few major enhancements and their value to the user. Bug fixes and other changes should be summarized in a
   bulleted list at the end of the release notes. Any limitations or incompatible changes in behavior should be explicitly noted.

   Consistent release note formatting is important. Here are some examples for reference:

   - [Example release notes for a major/minor release](https://github.com/projectcalico/calico/blob/v3.1.0/_includes/v3.1/release-notes/v3.1.0-release-notes.md)
   - [Example release notes for a patch release](https://github.com/projectcalico/calico/blob/7d5594dbca14cb1b765b65eb11bdd8239d23dfb3/_includes/v3.0/release-notes/v3.0.5-release-notes.md)

1. Add the generated file to git.

   ```
   git add release-notes/
   ```

# API Repository update

The `projectcalico/api` repository needs to be updated to stay in sync with the Calico API. The following steps will ensure that:

1. Ensure that you have the `gh` tool installed, configured, and authenticated. Instructions are here: https://cli.github.com/manual/
1. Clone the repository: `git clone -b release-v3.29 git@github.com:projectcalico/api.git calico-api-v3.29`
2. `cd` into the repository and run the `pr` make target from `Makefile.local`: `make -f Makefile.local pr CALICO_GIT_REF=<release tag name>`. `CALICO_GIT_REF` should be the tag for this release, e.g. `CALICO_GIT_REF=v3.29.0` if that's the version you just released.
3. The script will clone the upstream repository (i.e. `projectcalico/calico`), import the updated files, commit them, and create a PR for them
7. Once this is done, it will output a URL for a PR, which you can then review and get approved.

Note that if an auto-api PR already exists for this minor version, it will print an error about the PR existing already; this is fine, and the script will have updated the PR instead. Go to Github, find the PR manually, and review it to ensure everything looks correct, then have it merged.