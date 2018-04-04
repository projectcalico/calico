# Release process

## Resulting artifacts
Creating a new release creates the following artifact
* `calico/kube-controllers:$VERSION` container images (and the quay.io variant)

## Preparing for a release
Ensure that the branch you want to release from (typically master) is in a good state.
e.g. Update any pins in glide.yaml, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating the release
1. Choose a version e.g. `v1.0.0`
1. Create a tag: `make release-tag VERSION=v1.0.0`
1. Create the artifacts: `make release-build VERSION=v1.0.0`
1. Verify it: `make release-verify VERSION=v1.0.0`
1. Publish images: `make release-publish VERSION=v1.0.0`
1. Publish the GitHub release by following the link printed to screen.

