# Releasing a new version
## Optional - Updating dependencies
Makefile: 
- BUILD_CONTAINER_NAME?=calico/build:v0.18.0 - Currently, the startup.py script relies on the Python version of libcalico
- FELIX_CONTAINER_NAME?=calico/felix:2.0.0-beta.3
- LIBNETWORK_PLUGIN_CONTAINER_NAME?=calico/libnetwork-plugin:v1.0.0-beta-rc2
- Also, less commonly Bird, GoBGP and confd

glide.yaml
- Update any Go dependencies for Calicoctl here, e.g. libcalico-go
    - After updating glide.yaml run `glide up -v`

After performing these updates, make sure they are tested and commit the changes to `master`

## Releasing calico-containers (`calico/node` and `calicoctl`
1. Choose a version e.g. `export VERSION=v1.0.0`
2. Create a tag e.g. `git tag $VERSION`
3. Ensure that STs are passing
4. Run `make release-calicoctl` for the calicoctl release
4. Run `make release-caliconode` for the calico/node release
7. Push the tag e.g. `git push origin $VERSION`
8. Create a release on Github, using the tag which was just pushed and attach `calicoctl` to it.
