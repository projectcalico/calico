# Release Process

We have a goal of simultaneously serving multiple versions of the docs. This
means that multiple versions of the docs exist in sibling directories in the docs repo. This differs from what is normal, where only a single version
exists in the repo at a time and a git tag is created to reference old versions.

The versions that exist together are major or minor versions (e.g. v1.1, v1.2
and v2.0). There only exists a single patch version (or pre-release
alphas, betas and release candidates) for each major/minor version. When
we do a new patch release, the updates are made in-place.

## Types of Releases

There are four types of releases, each with a slightly different release process:

1. First release candidate for the next minor release (e.g. `vX.Y.0-rc1`)
2. Subsequent release candidates for the next minor release (e.g. `vX.Y.0-rcA` where `A > 1`)
3. Promoting a release candidate to a final release (e.g. `vX.Y.0`)
4. Patch release (e.g. `vX.Y.Z` where `Z > 0)

## 1. First release candidate for the next minor release

To cut the first release candidate, we will need to do three things:

1. Select and set versions of subcomponents.
2. Build and push images for `calico/node`.
3. Update the calico docs.

Since this is by far the longest release process, the steps are split up by section so that they are easier to follow. But (for now) they must be followed in this precise order!

### calico/node

1. Ensure master docs are passing semaphore tests.
1. Check out latest master locally.
1. Run `./release-scripts/do_release.py` to copy master directory to the new version directory. Commit
these new files in their own commit.
   > Note: The remaining changes below can all go in the same, separate commit.
1. Edit `_data/versions.yml`:
   1. Add a new section **at the end of the file**. (If a release is added to the top of the file it will become the 'Latest Release'). Be sure to add the date of the release in the description.
   1. Bump `currentReleaseStream` to this new release stream (e.g. `vX.Y`). 
1. Run `make -C calico_node release` to create the new `calico/node` images and release tar. 
Once complete, follow the instructions to push the new images.

### Docs

1. Add a section in `_config.yml` so that `page.version` will be set correctly in the new subdirectory.
1. Validate that the docs look ok. Run the site locally, check that master docs, new release docs, and last release docs look good.
1. Commit the changes. Be careful not to commit the release tar from earlier!
1. Open a pull request, make sure it passes CI and get it reviewed, then merge.

### Publish

1. Create a GitHub release on the Calico repo, and upload the release file (calico_node/release-<VERSION>.tgz)
1. Generate release notes and insert them into the GitHub release:
   1. Add a release note section to the GitHub PR description for all relevant GitHub pull requests. The 
      [PR template](.github/PULL_REQUEST_TEMPLATE.md) documents how to do this with the `release-note` tag.
   1. Run [generate-release-notes.py](https://github.com/tigera/process/blob/master/releases/generate-release-notes.py)
      with appropriate settings for MILESTONE and GITHUB_TOKEN environment variables (e.g. `export MILESTONE='Calico v2.5.0'`):
   1. Copy/paste the contents of `generated-release-notes.md` into the GitHub Release Notes.
1. Add the last minor release to the list of excluded releases in `_config_dev.yml`.

## 2. Subsequent release candidates for the next minor release

1. Add the new version to `_data/versions.yml`:
   - Add the date in the description.
   - Add the new version to `_data/versions.yml` (Remember to add the date in the description)
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Create a git tag, docker images, and release file by running `make -C calico_node release`. Follow the instructions to push the images and tag.
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Create a GitHub release on the Calico repo, and upload the release file (calico_node/release-<VERSION>.tgz)

## 3. Promoting a release candidate to a final release

1. Add a new `<option>` entry to the `<span class="dropdown">` in `_layouts/docwithnav.html` file. This step should NOT be performed until testing of the release is complete.
1. Modify the redirect in `/index.html` to point to your new release.
1. Move the section for the release in `_data/versions.yml` to the top of the file so that it will be the 'Latest Release'.
1. Update the master release stream section in `_data/versions.yml`.
1. Run `make add_redirects_for_latest VERSION=vX.Y` to update the redirects.
1. Test the changes locally then open a pull request, make sure it passes CI and get it reviewed.
1. Create a git tag, docker images, and release file by running `make -C calico_node release`.
   Follow the instructions to push the images and tag.
1. Now merge the PR - this will cause the live docs site to be updated (after a few minutes).
1. Create a GitHub release on the Calico repo, upload the release file (calico_node/release-<VERSION>.tgz), and post the updated
   release notes (see above for details).
1. Edit the [Calico Docs Custom Search Engine](https://cse.google.com/).
   1. Navigate to: search engine -> Search Features -> Refinements -> Add
   1. Add a new refinement name: vX.Y
   1. Navigate to: Setup -> Basics
   1. Under "Sites to search", select "Add", for the url use `docs.projectcalico.org/vX.Y`
   1. Choose vX.Y from the "Label" dropdown.

## 4. Patch release

Patch releases shouldn't include any new functionality, just bug fixes (except during pre-release testing).

The patch release process is the same as the [subsequent release candidates of the next minor release process](#2-subsequent-release-candidates-of-the-next-minor-release process). Follow those instructions above.