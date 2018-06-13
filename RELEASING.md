# Release process

There are two main steps to complete:

- [Building a release](#building-a-release)
- [Releasing debs and rpms](#releasing-debs-and-rpms)

## Preparing for a release

Checkout the branch from which you want to release. For a major or minor release,
you will need to create a new `release-vX.Y` branch based on the target Calico version.

Make sure the branch is in a good state, e.g. Update any pins in glide.yaml, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

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
   - Remove or clean up any messy commits - e.g. libcalico-go updates.
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
   - Remove or clean up any messy commits - e.g. libcalico-go updates.
   - Title the release the same as the tag - e.g. `v1.1.0`
   - Press "Publish release"

1. If this is the latest stable release, perform the following step to publish the `latest` images. **Do not perform
   this step for patches to older releases.**

   ```
   make VERSION=<version> release-publish-latest
   ```

## Releasing debs and rpms

### Build the packages

After completing the above `make release` process, you should produce and publish
the deb/rpm artifacts.

To build Debian and RPM packages for a release:

- Build the packages

  ```
  make deb rpm
  ```

  You should see debian/changelog and rpm/felix.spec being updated with the new version
  number and release notes, and packages built under `dist/`.

- Create a PR to get those changes, in particular the release notes, reviewed.
  If you need to make changes, do so, and run

  ```
  FORCE_VERSION=<new version> make deb rpm
  ```

  to rebuild packages with those changes in.  (Where `<new version>` is exactly
  the same as when you ran `make release VERSION=<new version>` above.)

- Once the changes are approved and any testing looks good, merge the PR.

### Publish the packages

For an official release, also build and publish the deb and rpm packages with the
following steps. These steps assume you have the correct GPG keys and accounts set up to
sign and publish the packages.

#### Debian packages

Perform the following steps in both the `dist/xenial` and `dist/trust` directories.

- Change into the desired `dist/<distro>` directory.

- Sign the package and `.changes` file with

  ```
  debsign -k<your key ID> *_source.changes
  ```

- Upload the signed package and `.changes` file with

  ```
  dput ppa:project-calico/calico-X.Y *_source.changes
  ```

  replacing `X.Y` with the actual series numbers.

It can take a long time for Launchpad to build and publish binary
packages. Usually about an hour, but occasionally many hours.

The PPA is only ready for use when the [PPA package detailspage](https://launchpad.net/~project-calico/+archive/ubuntu/calico-2.6/+packages) shows
all green ticks in its Build Status column.

#### RPMs

- Sign the RPMs

- Copy the signed RPMs to `/usr/share/nginx/html/rpm/calico-X.Y/x86_64` on the binaries server.

For more information, see [the full package release process](https://github.com/tigera/process/blob/master/releases/packages.md)
