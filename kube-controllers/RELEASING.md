# Release process

## Resulting artifacts

Creating a new release creates the following artifact

* `calico/kube-controllers:$VERSION` container images (and the quay.io variant)

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target Calico version.

Make sure the branch is in a good state, e.g. Update any pins in glide.yaml, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating a patch release

1. Choose a version e.g. `v1.0.1`

1. Create the release. This will generate release notes, a tag, build the code, and verify the artifacts.

   ```
   make VERSION=v1.0.1 release
   ```

1. Publish the release.

   ```
   make VERSION=v1.0.1 release-publish
   ```

1. Publish the release on GitHub by following the link printed to screen.
   - Copy the tag description, press edit, and paste it into the release body.
   - Remove or clean up any messy commits - e.g. libcalico-go updates.
   - Title the release the same as the tag - e.g. `v1.0.1`
   - Press "Publish release"

1. If this is the latest stable release, perform the following step to publish the `latest` images. **Do not perform
   this step for patches to older releases.**

   ```
   make VERSION=<version> release-publish-latest
   ```

## Creating a major / minor release

1. Choose a version e.g. `v1.1.0`

1. Create the release. This will generate release notes, a tag, build the code, and verify the artifacts.

   ```
   make VERSION=v1.1.0 PREVIOUS_RELEASE=v1.0.0 release
   ```

1. Publish the release.

   ```
   make VERSION=v1.1.0 release-publish
   ```

1. Publish the release on GitHub by following the link printed to screen.
   - Copy the tag description, press edit, and paste it into the release body.
   - Remove or clean up any messy commits - e.g. libcalico-go updates.
   - Title the release the same as the tag - e.g. `v1.1.0`
   - Press "Publish release"

1. If this is the latest stable release, perform the following step to publish the `latest` images. **Do not perform
   this step for patches to older releases.**

   ```
   make VERSION=<version> release-publish-latest
   ```
