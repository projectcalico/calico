# Release process

## Resulting artifacts
Creating a new release creates the following artifacts
* `calico/cni:$VERSION` and `calico/cni:latest` container images (and the quay.io variants)
* `calico` and `calico-ipam` binaries (stored in the `dist` directory).

## Preparing for a release
Ensure that the branch you want to release from (typically master) is in a good state.
e.g. Update the libcalico-go pin to the latest release in glide.yaml and run `glide up -v`, create PR, ensure test pass and merge.

You should have no local changes and tests should be passing.

## Creating the release
1. Choose a version e.g. `v1.0.0`
2. Create the release artifacts `make release VERSION=v1.0.0`. 
3. Follow the instructions that `make release` provides to push the artifacts and git tag.
4. Create a release on Github, using the tag which was just pushed. Attach the `calico` and `calico-ipam` binaries.
