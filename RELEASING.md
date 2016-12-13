# Release process

## Resulting artifacts
Creating a new release creates the following artifacts
* `calico/node:$VERSION` container image
* `calico/ctl` container image
* `calicoctl`  binary (stored in the `dist` directory.

## Preparing for a release
Ensure that the branch you want to release from (typically master) is in a good state.
e.g. Update the libcalico-go pin to the latest release in glide.yaml and run `glide up -v`, create PR, ensure test pass and merge.
or update other dependencies in the `Makefile` 
- `BUILD_CONTAINER_NAME?=calico/build:v0.18.0` - Currently, the startup.py script relies on the Python version of libcalico
- `FELIX_CONTAINER_NAME?=calico/felix:2.0.0`
- `LIBNETWORK_PLUGIN_CONTAINER_NAME?=calico/libnetwork-plugin:v1.0.0`
- Also, less commonly Bird, GoBGP and confd

You should have no local changes and tests should be passing.

## Creating the release
1. Choose a version e.g. `export VERSION=v1.0.0`
2. Create the release artifacts repositories `make release VERSION=$VERSION`. 
3. Follow the instructions to push the artifacts and git tag.
4. Create a release on Github, using the tag which was just pushed. 
5. Attach the following `calicoctl` binaries:
   - `calicoctl`
   - `calicoctl-darwin-amd64`
   - `calicoctl-windows-amd64.exe`
