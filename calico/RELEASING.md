# How to release Calico

> **NOTE:** These instructions apply only to Calico versions v3.2.0 or greater.
> For older releases, refer to the instructions in the corresponding `release-vX.Y` branch.

## Overview

This repository contains documentation and packaging, but no Calico code.

Releases of this repository still serve several important purposes. Namely, they provide:

- a single Calico release with user-facing release notes and documentation.
- a packaging of individual Calico component releases into a single `.tgz` file

## Prerequisites

To release Calico, you need **the following permissions**:

- Write access to the core repositories in the projectcalico/ GitHub organization.
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

- You must be a member of the Project Calico team on Launchpad, and
  have uploaded a GPG identity to your account, for which you have the
  secret key.

- You must be able to access binaries.projectcalico.org.

- You must have admin access to docs.projectcalico.org site on netlify.

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
  
You'll also need **several GB of disk space** (~7GB for v3.4.0, for example).

Some of the release scripts also require **tools to be installed** in your dev environment:

- [Install and configure](https://github.com/github/hub#installation) the GitHub `hub` tool.
- Create a [personal access token](https://github.com/settings/tokens) for Github and export it as the `GITHUB_TOKEN`
  env var (for example by adding it to your `.profile`).
- Install the "GitHub release" tool, `ghr`:

    ```
    go get -u github.com/tcnksm/ghr
    ```

Finally, the release process **assumes that your repos are checked out with name `origin`** for the git remote
for the main Calico repo.

## Releasing the subcomponents

Before attempting to create a Calico release you must do the following.

1. Choose a Calico version number, e.g. `v3.2.0`.

1. Verify that the code and GitHub are in the right state for releasing for the chosen version.

   - Make sure all components have up-to-date libcalico-go pins.
   - Make sure node has up-to-date pins for felix and confd.
   - Make sure felix and confd both have an up-to-date typha pin.
   - [Make sure the Milestone is empty](https://github.com/issues?utf8=%E2%9C%93&q=user%3Aprojectcalico+is%3Aopen+milestone%3A%22Calico+vX.Y.Z%22+) either by merging PRs, or kicking them out of the Milestone.
   - [Make sure that there are no pending cherry-pick PRs](https://github.com/issues?utf8=%E2%9C%93&q=user%3Aprojectcalico+label%3Acherry-pick-candidate) relevant to the release.
   - [Make sure there are no pending PRs which need docs](https://github.com/pulls?utf8=%E2%9C%93&q=is%3Apr+user%3Aprojectcalico+label%3Adocs-pr-required+) for this release.
   - [Make sure each PR with a release note is within a Milestone](https://github.com/issues?utf8=%E2%9C%93&q=user%3Aprojectcalico+no%3Amilestone+label%3Arelease-note-required).
   - [Make sure CI is passing](https://semaphoreci.com/calico) for the target release branch.

1. Select the appropriate component version numbers, and create any necessary releases. Follow the instructions
   in each repository for further information. (See recent release information, e.g. at
   https://docs.projectcalico.org/v3.7/release-notes/, for the set of components to consider releasing.)

   The following components _must_ use the same version number as the Calico version number
   chosen above, and thus must be re-released for every Calico release.

   - [calico/node](https://github.com/projectcalico/node/releases)
   - [calico/ctl](https://github.com/projectcalico/calicoctl/releases)
   - [calico/cni](https://github.com/projectcalico/cni-plugin/releases)
   - [calico/kube-controllers](https://github.com/projectcalico/kube-controllers/releases)
   - [calico/felix](https://github.com/projectcalico/felix/releases)
   - [calico/typha](https://github.com/projectcalico/typha/releases)
   - [calico/dikastes](https://github.com/projectcalico/app-policy/releases)
   - [calico/pod2daemon-flexvol](https://github.com/projectcalico/pod2daemon/releases)
   - [networking-calico](https://github.com/projectcalico/networking-calico/releases)

   The following components do not share a version with the Calico release, but are included in the documentation.

   - [flannel](https://github.com/coreos/flannel/releases)

## Building and publishing packages

1. Check out the [packaging
   repository](https://github.com/projectcalico/packaging).

1. In your environment, set `HOST` to the GCP name for
   binaries.projectcalico.org, `GCLOUD_ARGS` to the `--zone` and
   `--project` args needed to access that host, and `SECRET_KEY` to
   the secret key for a GPG identity that you have uploaded to your
   Launchpad account.

1. Establish GCP credentials so that gcloud with `HOST` and
   `GCLOUD_ARGS` can access binaries.projectcalico.org.

1. Run `make release-publish VERSION=<version>`, where `<version>` is
   the Calico version being released.

## Preparing to cut a Calico release

1. Check out the `master` branch of this repository and make sure it is up-to-date
   and [passing Semaphore CI](https://semaphoreci.com/calico/calico/branches/master).

   ```
   git checkout master && git pull origin master
   ```

Your next steps depend on the type of release:

- [Creating a new major/minor release](#major-minor)
  1. [Creating a candidate release branch](#candidate-branch)
  1. [Building and publishing a new major/minor release](#build)
  1. [Promoting a new major/minor release](#promoting)
- [Creating a patch release](#patch)


## <a name="major-minor"></a> Creating a new major / minor release

### <a name="candidate-branch"></a> Creating a candidate release branch

This section describes how to create a candidate release for a new major or minor release. This is typically done
at the same time that subcomponent release branches are cut, often well before the actual release is built and published.

1. Create a new branch off of the latest master.

   ```
   git checkout -b release-vX.Y
   ```

1. Update versioning information in `_data/versions.yml`.

   For example:

   ```
      - title: v2.1.0-pre-release
        note: ""
        components:
          typha:
            version: release-v2.1
        ... etc ...
   ```

1. Update the `version` in the `defaults` in `_config.yml` so that `page.version` will be set correctly:

   ```
   -
     scope:
       path: .
     values:
       version: vX.Y
   ```

1. In [netlify.toml](netlify.toml)
    1. set the `RELEASE_VERSION` environment variable to `vX.Y`.
    1. add the below redirect at the top of redirects.
    ```
       # unforced generic redirect of /vX.Y to /
       [[redirects]]
         from = "/vX.Y/*"
         to = "/:splat"
         status = 301
    ```

1. In [netlify/_redirects](_redirects) add a new for the new release following the other examples (Note: This page may vary with release, also just non-slash to slash redirects doesn't work. It needs to point to a page).
This makes sure that requests coming to `/archive/vX.Y` (without a slash) don't fail with 404.

1. Create the the release notes file. This does not need to be populated now but does need to exist.

   ```
   touch _includes/release-notes/<VERSION>-release-notes.md
   ```

1. If appropriate, update the list of tested versions for different platforms in the appropriate documents.

   - Kubernetes `getting-started/kubernetes/requirements.md`
   - OpenShift `getting-started/openshift/requirements.md`
   - OpenStack `getting-started/openstack/requirements.md`
   - Non-cluster hosts `getting-started/bare-metal/requirements.md`

1. Commit your changes and push the branch. For example:

   ```
   git commit -a -m "Update docs for vX.Y"
   git push origin release-vX.Y
   ```

### Publishing the candidate release branch

1. Check out to the candidate release branch that is created as per the instructions [here](#creating-a-candidate-release-branch).

   ```
   git checkout release-vX.Y
   ```

1. On netlify create a new site using the `release-vX.Y` branch (You should at least have write access to this repo for site creation)

1. Rename the randomly generated site name to follow the same naming convention as other releases (Ex: `calico-vX-Y`).

1. Ensure that the site is generated properly by visiting site URL (Ex. https://calico-vX-Y.netlify.app/archive/vX.Y/).

1. After ensuring that the site deployment is successful, in current production branch's [netlify.toml](netlify.toml), add below proxy rules for the release candidate at the top of `redirects` rules.

   ```toml
    [[redirects]]
      from = "/archive/vX.Y/*"
      to = "https://calico-vX-Y.netlify.app/archive/vX.Y/:splat"
      status = 200

    [[redirects]]
      from = "/vX.Y/*"
      to = "https://calico-vX-Y.netlify.app/vX.Y/:splat"
      status = 200
   ```

1. Ensure that these proxy rules are cherry-picked to master branch as well so that future releases, which would be cut from master, will have references to this releases.

1. Open a pull request to upstream production branch, get it reviewed and merged. This would make the candidate site docs available at `docs.projectcalico.org/archive/vX.Y/` (Note: the trailing slash)

### Promoting to be the latest release in the docs

This section describes how to create a new major or minor release. It assumes that the release branch has already been created
as described in the section above.

1. Checkout the previously created release branch.

   ```
   git checkout release-vX.Y
   ```

1. Add the previous release to `_data/archives.yaml`. Make this change in master as well.

1. Add the new version to the correct release section in `_data/versions.yml`.

1. Update the AUTHORS.md file. This will require `GITHUB_TOKEN` be set in your environment.

   ```
   make update-authors
   ```

1. Follow the steps in [writing release notes](#release-notes) to generate or update candidate release notes.

   Then, add the newly created release note file to git.

   ```
   git add _data/release-notes/<VERSION>-release-notes.md
   ```

1. Commit your changes. For example:

   ```
   git commit -m "Updates for release vX.Y.Z"
   ```

1. Push your branch and open a pull request to the upstream release-vX.Y branch. Get it reviewed and wait for it to pass CI.

1. Run the following on your local branch in order to build the release
   at the newly created commit.

   ```
   make release
   ```

   Then, publish the tag and release to github.

   ```
   make release-publish
   ```

1. Merge the PR.

1. On netlify locate `docs.projectcalico.org` site and the update `Production branch` in `Settings -> Build & deploy -> Deploy contexts` to `release-vX.Y` in  site settings and trigger the deployment.
(Note: This site contains `LATEST_RELEASE` environment variable in netlify UI, using which `netlify.toml` picks up the correct build for latest release.)
This will cause `docs.projectcalico.org` to be updated (after a few minutes). Validate that everything looks correct.

## Confirm the previous release is archived

1. Ensure that the site is accessible by visiting `docs.projectcalico.org/archive/<version>/`.

## <a name="patch"></a> Performing a "patch" release

### Creating the release

1. On a new branch, add the new version to the correct release section in `_data/versions.yml`

1. Follow the steps in [writing release notes](#release-notes) to generate candidate release notes.

   Then, add the newly created release note file to git.

   ```
   git add _includes/release-notes/<VERSION>-release-notes.md
   ```

1. Commit your changes. For example:

   ```
   git commit -m "Updates for release vX.Y.Z"
   ```

1. Push your branch and open a pull request. Get it reviewed and wait for it to pass CI.

1. Once reviewed and CI is passing, run the following on your local branch in order to build and publish the release
   at the newly created commit.

   ```
   make release
   ```

   Then, publish the tag and release.

   ```
   make release-publish
   ```
1. Merge the PR. This will cause the live docs site to be updated (after a few minutes).

# Release notes

Release notes for a Calico release contain notable changes across Calico repositories. To write
release notes for a given version, perform the following steps.

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

   A file called `<VERSION>-release-notes.md` will be created with the raw release note content.

   > **NOTE**: If you receive a ratelimit error, you can specify a `GITHUB_TOKEN` in the above command to
   > increase the number of allowed API calls. [See here for details](https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/).

1. Edit the generated file.

   The release notes should be edited to highlight a few major enhancements and their value to the user. Bug fixes and other changes should be summarized in a
   bulleted list at the end of the release notes. Any limitations or incompatible changes in behavior should be explicitly noted.

   Consistent release note formatting is important. Here are some examples for reference:

   - [Example release notes for a major/minor release](https://github.com/projectcalico/calico/blob/v3.1.0/_includes/v3.1/release-notes/v3.1.0-release-notes.md)
   - [Example release notes for a patch release](https://github.com/projectcalico/calico/blob/7d5594dbca14cb1b765b65eb11bdd8239d23dfb3/_includes/v3.0/release-notes/v3.0.5-release-notes.md)

# Verifying the release

The final steps in the process are to check it all worked.  This is important, so please don't skip it.

1. Checkout the relevant docs branch (i.e. the release-vX.Y branch)
1. run `make release-test`.  The release validation checks will run - they check for the presence of all the required binaries tarballs, tags, etc.  They do NOT check that the _contents_ of those are valid, but are a good test that the release process itself worked correctly.
1. check the output of the tests - if any test failed, dig in and understand why.
1. Kick off some e2e tests to test the contents of the release.
