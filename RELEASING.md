# Felix release artifacts

Running the main `make release` target, described below, guides you
through creating and distributing the following artifacts:

- A git tag for the release, annotated with the release note; ready to
  push to Github.
- File `dist/calico-felix-$VERSION.tgz`; the "PyInstaller bundle"
  containing the Felix binaries.  We attach that file to the
  Github release.
- Docker container images: `calico/felix:$VERSION` and
  `quay.io/calico/felix:$VERSION` containing the Felix binaries.  These
  are ready to push to Dockerhub and Quay.  They primarily form the input
  to the downstream `calico/node` build process but they could also
  be used to run Felix as a stand-alone container.

As a second step, running `make deb rpm` after `make release`, produces
debs and RPMs for the release which can be uploaded to our PPAs and
RPM repositories.  The debs and RPMs are created in subfolders of
`/dist/`.

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

- Consider whether you should update the libcalico-go pin in glide.yaml.
  If you do so, you should run `make update-vendor` to update the
  `glide.lock` file.  Be wary of any additional libraries that get
  revved if they aren't being pulled in by the libcalico-go update. At
  this late stage, it's safer to only update commit IDs that you're
  explicitly expecting (i.e. undo any changes that `make update-vendor`
  makes that you weren't expecting).  If in doubt consult a Felix/glide
  expert!

- Run `make release VERSION=<new version>` and follow the instructions.  This
  creates the annotated release tag, builds the release artifacts, and tells
  you what else you need to do to publish those.  The release script
  expects a version number of the form "2.0.0", with optional suffixes
  such as "-beta1-rc3".

# Felix packages for OpenStack and Host Protection deployments

Apart from OpenStack, the platforms that Calico targets are container-based, so
the container image artifacts already documented above are appropriate for
installing Felix on those platforms.  OpenStack installations, however, are
commonly based on packages, so for Calico with OpenStack we provide packages
for the OS platforms that are popular for OpenStack installs: Debian packages
for Ubuntu Trusty and Xenial, and RPM packages for CentOS 7 or RHEL 7.  These
packages can also be used for [Host Protection
deployments](https://docs.projectcalico.org/master/getting-started/bare-metal/bare-metal#installing-felix).

To build Debian and RPM packages for a release:

- Following the above, run `make deb rpm`.  You should see debian/changelog and
  rpm/felix.spec being updated with the new version number and release notes,
  and packages built under `dist/`.

- Create a PR to get those changes, in particular the release notes, reviewed.
  If you need to make changes, do so, and run

      FORCE_VERSION=<new version> make deb rpm

  to rebuild packages with those changes in.  (Where `<new version>` is exactly
  the same as when you ran `make release VERSION=<new version>` above.)

- Once the changes are approved and any testing looks good, merge the PR.
