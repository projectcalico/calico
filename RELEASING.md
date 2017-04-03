# Release process

## Resulting artifacts
Creating a new release creates the following artifacts:
- Container images:
  - `calico/node:$VERSION` and `calico/node:latest` 
  - `calico/ctl:$VERSION` and `calico/ctl:latest`
  - `quay.io/calico/node:$VERSION` and `quay.io/calico/node:latest`
  - `quay.io/calico/ctl:$VERSION` and `quay.io/calico/ctl:latest`
- Binaries (stored in the `dist` directory) :
  - `calicoctl`
  - `calicoctl-darwin-amd64`
  - `calicoctl-windows-amd64.exe`

## Preparing for a release
1. Make sure you are on the master branch and don't have any local uncommitted changes. e.g. Update the libcalico-go pin to the latest release in `glide.yaml` and run `glide up -v`, create PR, ensure test pass and merge.

2. Pre-requisits for pushing container images:
   - Make sure you have write access to calico orgs on Dockerhub and quay.io. 
   - Login using your dockerhub credentials.
   - `docker login` in your terminal. 
   - For quay.io: 
     1. Go to your account on quay.io
     2. Go to the account settings
     3. Go to the "settings" tab
     4. Click on "Generate Encrypted Password", it will popup a new sub-window
     5. Go to "Docker login" tab in that window
     6. Copy the command with encrypted password and paste it in your terminal
   - Now you should be able to push the container images with `docker push` command.

3. Update the sub-component versions in the Makefiles:
   - Makefile.calico-node:  
     - `CONFD_VER`
     - `BIRD_VER`
     - `GOBGPD_VER`
     - `FELIX_VER`
     - `LIBNETWORK_PLUGIN_VER`
   - Makefile.calicoctl:
     - `LIBCALICOGO_VER`
     - `GO_BUILD_VER`

4. If build fails during `make release`, make sure git tag is deleted before doing `make release` again. (This can be done with `git tag -d <tag>`)

## Creating the release
1. Choose a version e.g. `export VERSION=v1.0.0`
2. Create the release artifacts repositories `make release VERSION=$VERSION`. 
3. Follow the instructions to push the artifacts and git tag.
4. Create a release on Github, using the tag which was just pushed. 
5. Attach the following `calicoctl` binaries:
   - `calicoctl`
   - `calicoctl-darwin-amd64`
   - `calicoctl-windows-amd64.exe`
6. Add release notes for `calicoctl` and `calico/node`. Use `https://github.com/projectcalico/calicoctl/compare/<previous_release>...<new_release>` to find all the commit messages since the last release.
