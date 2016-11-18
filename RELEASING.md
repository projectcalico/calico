# Release Process

## Preparing for a release

1. Ensure master docs are passing semaphore tests.

2. Check out latest master locally.

## Creating the release

1. Run `python release-scripts/do_release.py`, which will walk through creation of the necessary
release directories, and will replace references to nightly artifacts with release ones.

2. Fix calico-cni binary links which are not updated by the release script (see [#147](https://github.com/projectcalico/calico/issues/147)).
To locate all offending CNI links, run the following:
   ```
   grep -r calico-cni\/releases vX.Y
   ```

3. Modify the new `vX.Y/releases/index.md` with the relevant versioning information
for this release. Ensure you change the header from `master` on that page as well.

4. Add a section in `_config.yaml` so that `page.version` will be set correctly in the new subdirectory:

   ```
   -
     scope:
       path: vX.Y
     values:
       version: vX.Y
   ```

5. Add a new `<option>` entry to the `<span class="dropdown">` in `_layouts/docwithnav.html`. (This step should be replaced by automation ASAP.)

6. Modify the redirect in `/index.html` to point to your new release.

7. Commit the changes made in steps 2-6.

8. QA the release. An easy way to do this is render the site locally.
You may also want to push this as a branch on a fork and publish your own github-pages
site for others to view under a different URL.

9. Open a pull request, make sure it passes CI, then merge.
