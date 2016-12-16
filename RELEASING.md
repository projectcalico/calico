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

# Felix packages for Calico with OpenStack

Apart from OpenStack, the platforms that Calico targets are container-based, so
the container image artifacts already documented above are appropriate for
installing Felix on those platforms.  OpenStack installations, however, are
commonly based on packages, so for Calico with OpenStack we provide packages
for the OS platforms that are popular for OpenStack installs: Debian packages
for Ubuntu Trusty and Xenial, and RPM packages for CentOS 7 or RHEL 7.

To build Debian and RPM packages for a release:

- Following the above, run `make deb rpm`.  You should see debian/changelog and
  rpm/felix.spec being updated with the new version number and release notes,
  and packages built under `dist/`.  If you then publish those packages (for
  which see below), you should also commit and push those changes, so that we
  have a record of when and how the packages were built.

To build Debian and RPM packages for any Git HEAD:

- Run `make deb rpm`.  You should see changes similar to the release case
  above, except that you probably don't want to save the temporary
  debian/changelog and rpm/felix.spec updates that are made.

To publish Debian packages:

- We publish Debian packages for Calico with OpenStack, on Ubuntu Trusty and
  Xenial, to PPAs (personal package archives) at
  https://launchpad.net/~project-calico.  This requires source packages to be
  signed with a GPG key of one of the members of "Project Calico", then
  uploaded to the PPA with "dput".  The steps are as follows.

- Become a member of "Project Calico" and upload your GPG key, if you
  aren't/haven't already.

- `debsign -k<KEY_ID> dist/{trusty,xenial}/*_source.changes`, where `<KEY_ID>`
  is enough of your GPG key name to uniquely identify it.

- `dput ppa:project-calico/<PPA> dist/{trusty,xenial}/*_source.changes`, where
  `<PPA>` is the target PPA, such as 'calico-1.4'.

To publish RPM packages:

- We publish RPM packages for Calico with OpenStack, on CentOS 7 or RHEL 7, to
  repositories on binaries.projectcalico.org.  Each package must be signed with
  the GPG key for the repository that it is being published in, as indicated by
  the 'key' file in the repository root.  (Recently this has been the key
  BCBB6892, for which the signing key is available on jenkins-slave1.)  The
  steps are as follows.

- `rpm --define '_gpg_name <KEY_ID>' --resign dist/rpms/RPMS/*/*.rpm`, where
  `<KEY_ID>` is enough of the GPG signing key name to uniquely identify it.

- Copy signed RPMs to the appropriate place under
  `/usr/share/nginx/html/rpm/<REPO_NAME>` on binaries.projectcalico.org.

- Run `createrepo .` in `/usr/share/nginx/html/rpm/<REPO_NAME>` on
  binaries.projectcalico.org, to update the repository's metadata.
