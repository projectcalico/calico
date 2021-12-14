# Release process

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target Calico version.

Make sure the branch is in a good state. You should have no local changes and tests should
be passing.

## Building a release

### Creating a patch release

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
   - Copy the tag description or the generated release notes file, press edit, and paste it into the release body.
   - Remove or clean up any messy commits.
   - Title the release the same as the tag - e.g. `v1.0.1`
   - Press "Publish release"

1. If this is the latest stable release, perform the following step to publish the `latest` images. **Do not perform
   this step for patches to older releases.**

   ```
   make VERSION=<version> release-publish-latest
   ```

### Creating a major / minor release

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
   - Copy the tag description or the generated release notes file, press edit, and paste it into the release body.
   - Remove or clean up any messy commits.
   - Title the release the same as the tag - e.g. `v1.1.0`
   - Press "Publish release"

1. If this is the latest stable release, perform the following step to publish the `latest` images. **Do not perform
   this step for patches to older releases.**

   ```
   make VERSION=<version> release-publish-latest
   ```

# Debian and RPM packages

For the preparation of Debian and RPM packages, see
https://github.com/projectcalico/packaging.

(Tigera builds and publishes packages for each Calico release as a
whole, once all the Calico components have been released.)
