# Typha release artifacts

Running the main `make release` target, described below, guides you
through creating and distributing the following artifacts:

- A git tag for the release, annotated with the release note; ready to
  push to Github.
- File `bin/calico-typha`; the static binary relase, which we attach to 
  the GitHub release.
- Docker container images: `calico/typha:$VERSION` and
  `quay.io/calico/typha:$VERSION` containing the Typha binaries.  These
  are ready to push to Dockerhub and Quay.

# Typha release process

In a nutshell:

- We make a Typha release by creating and pushing an annotated Git tag.  The
  name of the tag is the Typha version for that release, and the tag content is
  the release notes.

- There are no hardcoded version numbers anywhere in the codebase (except in
  packaging files, as described next).  Instead, build processes generate a
  unique and monotonic Typha version number from the last Git tag and the
  number of commits since that tag - equally whether they are processing
  release code (i.e. there is a release tag on HEAD) or code in between
  releases, or since the last release.

So, to make a Typha release:

- Consider whether you should update the libcalico-go pin in glide.yaml.
  If you do so, you should run `make update-vendor` to update the
  `glide.lock` file.  Be wary of any additional libraries that get
  revved if they aren't being pulled in by the libcalico-go update. At
  this late stage, it's safer to only update commit IDs that you're
  explicitly expecting (i.e. undo any changes that `make update-vendor`
  makes that you weren't expecting).  If in doubt consult a Typha/glide
  expert!

- Run `make release VERSION=<new version>` and follow the instructions.  This
  creates the annotated release tag, builds the release artifacts, and tells
  you what else you need to do to publish those.  The release script
  expects a version number of the form "2.0.0", with optional suffixes
  such as "-beta1-rc3".
