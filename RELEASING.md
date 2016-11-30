# Felix release artifacts

The artifacts of a Felix release are a tarball (aka PyInstaller
bundle) and a Docker container image, both containing the Felix
executable(s) .

# Felix release process

In a nutshell:

- We make a Felix release by creating and pushing an annotated Git tag.  The
  name of the tag is the Felix version for that release, and the tag content is
  the release notes.

- There are no hardcoded version numbers anywhere in the codebase (except in
  packaging files, as described next).  Instead, build processes generate a
  unique and monotonic Felix version number from the last Git tag and the
  number of commits since that tag - equally whether they are processing
  release code (i.e. there is a release tag on HEAD) or code in between
  releases, or since the last release.

- The building of Debian and RPM packages is considered to be an optional
  separate step from the release tagging above.

So, to make a Felix release:

- Run `make release VERSION=<new version>` and follow the instructions.  This
  creates the annotated release tag, builds the release artifacts, and tells
  you what else you need to do to publish those.

To build Debian and RPM packages for a release:

- Following the above, run `make deb rpm`.  You should see debian/changelog and
  rpm/felix.spec being updated with the new version number and release notes,
  and packages built under `dist/`.  If you then publish those packages, you
  should also commit and push those changes, so that we have a record of when
  and how the packages were built.

To build Debian and RPM packages for any Git HEAD:

- Run `make deb rpm`.  You should see changes similar to the release case
  above, except that you probably don't want to save the temporary
  debian/changelog and rpm/felix.spec updates that are made.
