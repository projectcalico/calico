# How to release Calico

> **NOTE:** These instructions apply only to Calico versions v3.2.0 or greater.
> For older releases, refer to the instructions in the corresponding `release-vX.Y` branch.

## Overview

This repository contains documentation and packaging, but no Calico code.

Releases of this repository still serve several important purposes. Namely, they provide:

- a single Calico release with user-facing release notes and documentation.
- a packaging of individual Calico component releases into a single `.tgz` file

## Prerequisites

Before attempting to create a Calico release you must do the following.

1. Choose a Calico version number, e.g. `v3.2.0`.

1. Select the appropriate component version numbers, and create any necessary releases.

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

   The following components do not yet use the same versioning as the Calico repo, and
   so the version to include may differ.

   - [networking-calico](https://github.com/projectcalico/networking-calico)

   The following components do not share a version with the Calico release, but are included in the documentation.

   - [flannel](https://github.com/coreos/flannel/releases)

## Preparing to cut a Calico release


1. Check out the `master` branch of this repository and make sure it is up-to-date
   and [passing Semaphore CI](https://semaphoreci.com/calico/calico/branches/master).

   ```
   git checkout master && git pull origin master
   ```

Your next steps depend on the type of release:
- [Creating a new major/minor release](#major-minor)
- [Promoting a release candidate](#promoting)
- [Creating a patch release](#patch)

## <a name="major-minor"></a> Creating a new major / minor release

This section describes how to create a new major or minor release, which may or may not
be a release candidate.

1. Create a new branch off of the latest master.

   ```
   git checkout -b <NEW_PERSONAL_BRANCH>
   ```

1. Create the release-versioned directories for the documentation, copying from master directories.

   ```
   python2 ./release-scripts/do_release.py
   ```

1. Add the new version to the bottom of `_data/versions.yml`.

   This ensures the release is not listed as the "Latest release" in the documentation. Populate the
   section with the chosen component versions for this release.

   For example:

   ```
    v2.1
      - title: v2.1.0-rc1
        ... etc ...
   ```

1. Add a section in `_config.yml` so that `page.version` will be set correctly in the new subdirectory:

   ```
   -
     scope:
       path: vX.Y
     values:
       version: vX.Y
   ```

1. Follow the steps in [writing release notes](#release-notes) to generate candidate release notes.

   Then, add the newly created release note file to git.

   ```
   git add _data/<VERSION>/release-notes/<VERSION>-release-notes.md
   ```

1. Commit your changes. For example:

   ```
   git commit -m "Updates for release vX.Y"
   ```

1. Run the following on your local branch in order to build and publish the release
   at the newly created commit.

   ```
   make RELEASE_STREAM=vX.Y release
   ```

   Then, publish the tag and release.

   ```
   make RELEASE_STREAM=vX.Y release-publish
   ```

   Follow the steps on screen, which will instruct you to upload
   the `release-<VERSION>.tgz` artifact to the GitHub release using the GitHub UI, and
   populate the GitHub release with the release notes from earlier.

1. Push your branch and open a pull request. Get it reviewed and wait for it to pass CI.

   Once reviewed and CI is passing, merge the PR. This will cause the
   live docs site to be updated (after a few minutes).


1. Edit the [Calico Docs Custom Search Engine](https://cse.google.com/).
   1. Navigate to: search engine -> Search Features -> Refinements -> Add
   1. Add a new refinement name: vX.Y
   1. Navigate to: Setup -> Basics
   1. Under "Sites to search", select "Add", for the url use `docs.projectcalico.org/vX.Y`
   1. Choose vX.Y from the "Label" dropdown.

1. Edit `_config_dev.yml` to exclude the previous release.

If the release is not a release candidate but in fact a stable release, then you must also
follow the steps in the next section for promoting a release candidate to a final release.

## <a name="promoting"></a> Promoting a release candidate to a final release

The following steps outline how to promote a major / minor release candidate to the latest
release in the documentation. Perform these steps on a branch off of master.

### Promoting to the latest release

1. Add TWO new `<option>` entries to the `<span class="dropdown">` in `_layouts/docwithnav.html` file.

1. Modify the redirect in `/index.html` to point to your new release.

1. Move the section for the release in `_data/versions.yml` to the top of the file so that it will be the 'Latest Release'.

1. Run `make add_redirects_for_latest VERSION=vX.Y` to update the redirects.

1. Commit your changes and open a pull request, make sure it passes CI and get it reviewed.

   Once reviewed and CI has passed, merge the PR. This will cause the live docs site to be updated (after a few minutes).

### Updating canonical redirects

1. Pull the latest master and check out a _new_ branch.

1. Update the canonical URLs to point at the new release.

   Run the following command  to switch the canonical URLs to the latest release version number. Pass in the number of the previous
   release via `OLD` and the number of the current latest release via `NEW`.

   ```
   make update_canonical_urls OLD=vX.Y NEW=vX.Y
   ```

   Example: `make update_canonical_urls OLD=v3.0 NEW=v3.1`, where `3.0` was the previous latest and `3.1` is the new latest release.

1. Submit a PR with the canonical link changes, make sure it passes CI, and get it reviewed.

   ```
   make htmlproofer
   ```

   > NOTE: You may experience `htmlproofer` errors at this stage if a page was deleted or renamed in the `master` directory.
   >       Such errors can also occur if a page was deleted or renamed in the latest release and the `master`
   >       directories but the canonical links were not updated according to the instructions in CONTRIBUTING_DOCS.md.
   >       Modify the `canonical_url` metadata of the pages that error out so that they point to valid locations. If the
   >       page was deleted, adjust the version number of the canonical URLs to the final copy of the page.
   >       If the page was renamed, update the canonical URLs to the new path.

## <a name="patch"></a> Performing a "patch" release

### Creating the release

1. On a new branch, add the new version to the correct release section in `_data/versions.yml`

1. Follow the steps in [writing release notes](#release-notes) to generate candidate release notes.

   Then, add the newly created release note file to git.

   ```
   git add _data/<VERSION>/release-notes/<VERSION>-release-notes.md
   ```

1. Commit your changes. For example:

   ```
   git commit -m "Updates for release vX.Y"
   ```

1. Run the following on your local branch in order to build and publish the release
   at the newly created commit.

   ```
   make RELEASE_STREAM=vX.Y release
   ```

   Then, publish the tag and release.

   ```
   make RELEASE_STREAM=vX.Y release-publish
   ```

   Follow the steps on screen, which will instruct you to upload
   the `release-<VERSION>.tgz` artifact to the GitHub release using the GitHub UI, and
   populate the GitHub release with the release notes from earlier.

1. Push your branch and open a pull request. Get it reviewed and wait for it to pass CI.

   Once reviewed and CI is passing, merge the PR. This will cause the
   live docs site to be updated (after a few minutes).

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
   make RELEASE_STREAM=vX.Y release-notes
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
