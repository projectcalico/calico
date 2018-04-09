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
1. Add the new version to `_data/versions.yml` (add the date of the release in the description)
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
1. Add a section in `_config.yml` so that `page.version` will be set correctly in the new subdirectory:
    ```
       -
         scope:
           path: vX.Y
         values:
           version: vX.Y
    ```
1. Update `currentReleaseStream` in `_data/versions.yml`. The correct format is v`Major`.`Minor`, e.g. `v2.5`.
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
1. Move the section for the release in `_data/versions.yml` to the top of the file so that it will be the 'Latest Release'.
1. Run `make add_redirects_for_latest VERSION=vX.Y` to update the redirects.
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Create a git tag, docker images, and release file by running `make -C calico_node release`.
   Follow the instructions to push the images but DO NOT PUSH THE TAG YET.
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Run `make update_canonical_urls OLD=vX.Y NEW=vX.Y` to switch the canonical URLs to the latest release version number. Pass in the number of the previous release via `OLD` and the number of the current latest release via `NEW`. Example: `make update_canonical_urls OLD=v3.0 NEW=v3.1`, where `3.0` was the previous latest and `3.1` is the new latest release.
1. Test the changes locally by running `htmlproofer` then open a pull request, make sure it passes CI and get it reviewed.
    NOTE: You may experience `htmlproofer` errors at this stage if a page was deleted or renamed in the `master` directory. Such errors can also occur if a page was deleted or renamed in the latest release and the `master` directories but the canonical links were not updated according to the instructions in CONTRIBUTING_DOCS.md. Modify the `canonical_url` metadata of the pages that error out so that they point to valid locations. If the page was deleted, adjust the version number of the canonical URLs to the final copy of the page. If the page was renamed, update the canonical URLs to the new path.

### Performing a "patch" release
Patch releases shouldn't include any new functionality, just bug fixes (expect during pre-release testing).
1. Add the new version to `_data/versions.yml`:
   - Add the date in the description.
   - Add the new version to `_data/versions.yml` (Remember to add the date in the description)
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Create a git tag, docker images, and release file by running `make -C calico_node release`. Follow the instructions to push the images but DO NOT PUSH THE TAG YET.
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Push the tag.
1. Create a GitHub release on the Calico repo, and upload the release file (calico_node/release-<VERSION>.tgz)
