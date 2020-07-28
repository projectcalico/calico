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

1. Check out to the candidate release branch that is created as per the instructions [here](#-creating-a-candidate-release-branch). 

   ```
   git checkout release-vX.Y
   ```
   
1. Enable branch deployments for this branch on netlify by adding branch name to `Branch deploys` context in `Deploy contexts`. This setting can be found in in `Build & deploy` tab of site settings sidebar.

1. In [netlify.toml](netlify.toml), set the `RELEASE_VERSION` environment variable to vX.Y.
   
1. Commit your changes. For example:

   ```
   git commit -m "build vX.Y candidate"
   ```

1. Commit your changes and push the branch. This would trigger a branch deployment of the candidate branch. Ensure that the site is generated properly by visiting the branch deploy site URL. 

1. After ensuring that the branch deployment is successful, in current production branch's [netlify.toml](netlify.toml), add below proxy rules for the release candidate, at the top of `redirects` rules. Ensure that `force` is False

   ```toml
    [[redirects]]
      from = "/archive/vX.Y/*"
      to = "https://release-vX-Y--calico.netlify.app/archive/vX.Y/:splat"
      status = 200
      force = false
    
    [[redirects]]
      from = "/v3.14/*"
      to = "https://release-vX-Y--calico.netlify.app/vX.Y/:splat"
      status = 200
      force = false
   ```
   
1. Open a pull request to upstream production branch, get it reviewed and merged. This would generate the docs for the candidate at `/archive/vX.Y/` (Note: the trailing slash)

### Promoting to be the latest release in the docs

This section describes how to create a new major or minor release. It assumes that the release branch has already been created
as described in the section above.

- Move current release to the archives

1. Checkout the previously created release branch.

   ```
   git checkout release-vX.Y
   ```

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

1. In [netlify.toml](netlify.toml):
      
      1. Set the `RELEASE_VERSION` environment variable to new version.
            
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

1. On netlify update `Production branch` in Deploy contexts to `release-vX.Y` in docs.projectcalico.org site settings.
This will cause docs.projectcalico.org to be updated (after a few minutes). Validate that everything looks correct.

## Adding the previous release to docs.projectcalico.org/archive

1. Enable branch deployments for previous release branch on netlify by adding branch name to `Deploy contexts` in site settings.
 
1. Checkout to previous release branch. Add a commit to the branch, an empty commit if necessary (to trigger the branch deploy). 

1. Open a pull requests to upstream previous release branch, get it reviewed and merged. This triggers branch deployment for the previous release.

1. Ensure branch deployment is done by visiting to `<previous-release-branch-name>--calico.netlify.app`. (Note: For branch deploy site CSS might not load properly, but it'll show properly during the proxy). 

1. Check out to production branch. 
   ```
   git checkout release-vX.Y
   ```

1. Add a new stanza to [netlify.toml](netlify.toml) to configure the proxy to the previous release.

   ```toml
    [[redirects]]
      from = "/archive/<previous-release>/*"
      to = "https://<previous-release-branch>--calico-test.netlify.app/:splat"
      status = 200
      force = true
      headers = {X-From = "Netlify"}
   ```
1. Commit your changes and open a PR against upstream master.

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
