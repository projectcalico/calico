# Release Process
We have a goal of simultaneously serving multiple versions of the docs. This
means that there are multiple versions of the docs existing next to each other
in the docs repo. This differs from what is normal, where only a single version
exists in the repo at a time and a git tag is created to reference old versions.

The versions that exist together are major or minor versions (e.g. v1.1, v1.2
and v2.0). There only exists a single patch version (or pre-release
alphas, betas and release candidates) for each major/minor version. When
we do a new patch release, the updates are made in-place.

## Preparing for a release
1. Ensure master docs are passing semaphore tests.
1. Check out latest master locally.

## Creating the release
### When doing a major/minor release ONLY
These steps are for creating a new major/minor release, with the expectation
that a release candidate will be created, published and tested before the final
release is announced.

1. Run `./release-scripts/do_release.py` to copy master directory to the new version directory
1. Add the new version to `_data/versions.yaml` (add the date of the release in the description)
   - Add new versions that are a release candidate to the end of the file.
     If a release is added to the top of the file it will become the 'Latest Release'.
   - Make sure new release candidate versions are added to the top of the new release section (otherwise
     yaml will incorrectly identify an older release candidate):
     ```
      v2.X
        - title: v2.X.0-rc2
          ... etc ...

        - title: v2.X.0-rc1
          ... etc ...
     ```
1. Add a section in `_config.yaml` so that `page.version` will be set correctly in the new subdirectory:
    ```
       -
         scope:
           path: vX.Y
         values:
           version: vX.Y
    ```
1. Update the `RELEASE_STREAM` variable at the top of calico_node/Makefile to the new major/minor version.
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Run `make -C calico-node release` - **do not push the git tag yet** - and follow the instructions to:
   1. Create release docker images (do not push the `latest` tag yet).
   1. Create the release file
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Push the tag.
1. Create a GitHub release on the Calico repo, and upload the release file (calico_node/release-<VERSION>.tgz)
1. Generate release notes and insert them into the GitHub release:
   1. Add a release note section to the GitHub PR description for all relevant GitHub pull requests. The PR template
      documents how to do this with the `release-note` tag.
   1. Run [generate-release-notes.py](https://github.com/tigera/process/blob/master/releases/generate-release-notes.py)
      with appropriate settings for MILESTONE and GITHUB_TOKEN environment variables (e.g. `export MILESTONE='Calico v2.5.0'`):
   1. Copy/paste the contents of `generated-release-notes.md` into the GitHub Release Notes.
1. Edit the [Calico Docs Custom Search Engine](https://cse.google.com/).
   1. Navigate to: search engine -> Search Features -> Refinements -> Add
   1. Add a new refinement name: vX.Y
   1. Navigate to: Setup -> Basics
   1. Under "Sites to search", select "Add", for the url use `docs.projectcalico.org/vX.Y`
   1. Choose vX.Y from the "Label" dropdown.
1. Edit `_config_dev.yml` to exclude the previous release.

### Promoting a release candidate to a final release
1. Add a new `<option>` entry to the `<span class="dropdown">` in `_layouts/docwithnav.html` file. This step should NOT be performed until testing of the release is complete.
1. Modify the redirect in `/index.html` to point to your new release.
1. Move the section for the release in `_data/versions.yaml` to the top of the file so that it will be the 'Latest Release'.
1. Update the master release stream section in `_data/versions.yaml`.
1. Run `make add_redirects_for_latest VERSION=vX.Y` to update the redirects.
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Create a git tag, docker images, and release file by running `make -C calico_node release`.
   Follow the instructions to push the images but DO NOT PUSH THE TAG YET.
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Push the tag.
1. Create a GitHub release on the Calico repo, upload the release file (calico_node/release-<VERSION>.tgz), and post the updated
   release notes (see above for details).

### Performing a "patch" release
Patch releases shouldn't include any new functionality, just bug fixes (expect during pre-release testing).
1. Add the new version to `_data/versions.yaml`:
   - Add the date in the description.
   - Add the new version to `_data/versions.yaml` (Remember to add the date in the description)
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Create a git tag, docker images, and release file by running `make -C calico_node release`. Follow the instructions to push the images but DO NOT PUSH THE TAG YET.
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Push the tag.
1. Create a GitHub release on the Calico repo, and upload the release file (calico_node/release-<VERSION>.tgz)
