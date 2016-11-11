# Release process

## Resulting artifacts
Creating a new release creates the following artifact
* `calico/kube-policy-controller:$VERSION` container images (and the quay.io variant)

## Preparing for a release
Ensure that the branch you want to release from (typically master) is in a good state.
e.g. Update the libcalico pins in `build.sh`, create PR, ensure tests pass and merge.

You should have no local changes and tests should be passing.

## Creating the release
1. Choose a version e.g. `v1.0.0`
2. Create the release artifacts repositories `make release VERSION=v1.0.0`. 
3. Follow the instructions from `make release` to push the artifacts and git tag.
4. Create a release on Github, using the tag which was just pushed.

