# Building Calico components

This document describes how to build the following Calico components from their
source code.

-  [typha](https://github.com/projectcalico/typha)
-  [felix](https://github.com/projectcalico/felix)
-  [CNI plugins](https://github.com/projectcalico/cni-plugin)
-  [confd](https://github.com/projectcalico/confd) (Calico specific fork)
-  [Calico BGP daemon](https://github.com/projectcalico/calico-bgp-daemon)
-  [bird and bird6](https://github.com/projectcalico/bird) (Calico specific fork)
-  [libnetwork plugin](https://github.com/projectcalico/libnetwork-plugin)
-  [calicoctl](https://github.com/projectcalico/calicoctl)
-  [calico/node](https://github.com/projectcalico/node)

See each component repository for more details on the build process for that component.

## Requirements

These build instructions assume you have a Linux build environment
with:

-  Docker 1.12+
-  git
-  make

#### Build environment

We recommend checking out all of the code to a common base directory.  The instructions
below assume the environment variable $BASEDIR has been set.  For example:

```
export BASEDIR=~/go/src/github.com/projectcalico
```

This directory should exist:

```
mkdir -p $BASEDIR
```

These instructions describe how to build a particular release or Calico.  This comprises
of multiple sub components each individually versioned.  To determine which
particular tag (version) of code to checkout for each repo, consult the Releases page of the
appropriate version of the [Calico documentation](https://docs.projectcalico.org)

Define the following environment variables that describe the versions of each of the
components that you are building (the instruction below use these):

```
VERSION_TYPHA
VERSION_FELIX
VERSION_CNI
VERSION_CONFD
VERSION_BIRD
VERSION_BGP_DAEMON
VERSION_LIBNETWORK
VERSION_CALICOCTL
VERSION_CALICO
```

For example, the v2.3.0 release of Calico would define the following:

```
export VERSION_TYPHA=v0.2.0
export VERSION_FELIX=2.3.0
export VERSION_CNI=v1.9.1
export VERSION_CONFD=v0.12.1-calico0.1.0
export VERSION_BIRD=v0.3.1
export VERSION_BGP_DAEMON=v0.2.1
export VERSION_LIBNETWORK=v1.1.0
export VERSION_CALICOCTL=v1.3.0
export VERSION_CALICO=v2.3.0

```

#### Build targets
The following are the standard `Makefile` targets that are in every project repository.

* `make build`: build the binary for the current architecture. Normally will be in `bin/` or `dist/` and named `NAME-ARCH`, e.g. `felix-arm64` or `typha-amd64`. If there are multiple OSes available, then named `NAME-OS-ARCH`, e.g. `calicoctl-darwin-amd64`.
* `make build ARCH=<ARCH>`: build the binary for the given `ARCH`. Output binary will be in `bin/` or `dist/` and follows the naming convention listed above.
* `make build-all`: build binaries for all supported architectures. Output binaries will be in `bin/` or `dist/` and follow the naming convention listed above.
* `make image`: create a docker image for the current architecture. It will be named `NAME:latest-ARCH`, e.g. `calico/felix:latest-amd64` or `calico/typha:latest-s390x`. If multiple operating systems are available, will be named `NAME:latest-OS-ARCH`, e.g. `calico/ctl:latest-linux-ppc64le`
* `make image ARCH=<ARCH>`: create a docker image for the given `ARCH`. Images will be named according to the convention listed above.
* `make image-all`: create docker images for all supported architectures. Images will be named according to the convention listed above in `make image`.
* `make push IMAGETAG=<IMAGETAG>`: push the docker image for the current architecture to all registries, specifically docker hub and quay.io. The images will be named `NAME:IMAGETAG-ARCH`, e.g. `make push IMAGETAG=foo` will push images `calico/felix:foo-amd64` or `calico/typha:foo-ppc64le`. 
* `make push IMAGETAG=<IMAGETAG> ARCH=<ARCH>`: push the docker image for the given `ARCH` to all registries, specifically docker hub and quay.io. The images will be named `NAME:IMAGETAG-ARCH`, e.g. `make push IMAGETAG=foo ARCH=arm64` will push images `calico/felix:foo-arm64`. 
* `make push-all IMAGETAG=<IMAGETAG>`: push the docker images for all supported architectures to all registries, specifically docker hub and quay.io. The images will be named `NAME:IMAGETAG-ARCH`, e.g. `make push-all IMAGETAG=foo` will push images `calico/felix:foo-arm64` and `calico/felix:foo-amd64` and etc. 
* `make tag-images IMAGETAG=<IMAGETAG>`: tag the docker image built locally, usually as `latest`, for the current architecture to `$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)` and `quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)`. e.g. `make tag-images IMAGETAG=foo` will tag the locally built image to `calico/felix:foo-amd64` or `calico/typha:foo-ppc64le`. 
* `make tag-images IMAGETAG=<IMAGETAG> ARCH=<ARCH>`: tag the docker image built locally for the given `ARCH` to `$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)` and `quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)`. e.g. `make tag-images IMAGETAG=foo ARCH=arm64` will tag the locally built `arm64` image to `calico/felix:foo-arm64` or `calico/typha:foo-arm64`.
* `make tag-images-all IMAGETAG=<IMAGETAG>`: tag locally built images for all supported architectures to `$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)` and `quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)`.
* `make test`: run all tests
* `make ci`: run all CI steps, likely other targets. **WARNING:** It is **not** recommended to run `make ci` locally, as the actions it takes may be destructive, e.g. pushing out images. For your safety, it only will work if you run `make ci CONFIRM=true`, which only should be run by the proper CI system.


NB: Some are still in the process of being added.

## Build instructions

The following sections should be followed in order as there are cross dependencies
between the various components that have been built.

### 1. typha

To build typha, clone the typha repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_TYPHA git@github.com:projectcalico/typha.git
cd typha
```

Build the `calico/typha` docker image (which also builds the associated binaries) and
retag the image with the correct version.

```
make clean
make calico/typha
docker tag calico/typha calico/typha:$VERSION_TYPHA
```

#### Artifacts

This builds the following:

-  The `calico/typha` Docker image
-  The `bin/calico-typha` binary (included in the Docker image)

### 2. felix (used in the calico/node image)

To build felix, clone the felix repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_FELIX git@github.com:projectcalico/felix.git
cd felix
```

Build the `calico/felix` docker image (which also builds the associated binaries) and
retag the image with the correct version.

```
make clean
make calico/felix
docker tag calico/felix calico/felix:$VERSION_FELIX
```

#### Artifacts

This builds the following:

-  The `calico/felix` Docker image
-  The `bin/calico-felix` binary (included in the Docker image)

### 3. CNI plugins

To build Calico CNI plugins, clone the felix repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_CNI git@github.com:projectcalico/cni-plugin.git
cd cni-plugin
```

Build the `calico/cni` docker image (which also builds the associated binaries) and
retag the image with the correct version.

```
make clean
make docker-image
docker tag calico/cni calico/cni:$VERSION_CNI
```

#### Artifacts

This builds the following:

-  The `calico/cni` Docker image
-  The `dist/calico` binary (included in the Docker image)
-  The `dist/calico-ipam` binary (included in the Docker image)

The following binaries (included in the Docker image) are pulled directly from the
[containernetworking/cni releases](https://github.com/containernetworking/cni/releases):

-  The `dist/flannel` binary (included in the Docker image)
-  The `dist/host-local` binary (included in the Docker image)
-  The `dist/loopback` binary (included in the Docker image)

The following binary (included in the Docker image) is pulled from the [Calico CNI plugin releases page](https://github.com/projectcalico/cni-plugin/releases/download/v1.9.0/portmap)
and is a build of the [containernetworking/cni portmap plugin](https://github.com/containernetworking/plugins/tree/master/plugins/meta/portmap).  The build
process for this plugin has yet to be formalized:

-  The `dist/portmap` binary (included in the Docker image)

### 4. confd (used in the calico/node image)

To build confd, clone the confd repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_CONFD git@github.com:projectcalico/confd.git
cd confd
```

Build the `confd` static binary.

```
make bin/confd
```

#### Artifacts

This builds the following:

-  The `bin/confd` binary

### 5. calico-bgp-daemon (used in the calico/node image)

To build the Calico BGP daemon, clone the calico-bgp-daemon repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_BGP_DAEMON git@github.com:projectcalico/calico-bgp-daemon.git
cd calico-bgp-daemon
```

Build the `calico-bgp-daemon` static binary.

```
﻿make build-containerized
```

#### Artifacts

This builds the following:

-  The `dist/calico-bgp-daemon` binary
-  The `dist/gobgp` binary


### 6. bird (used in the calico/node image)

To build the bird and bird6 binaries, clone the bird repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_BIRD git@github.com:projectcalico/bird.git
git clone git@github.com:projectcalico/bird.git
cd bird
```

Build the `bird`, `bird6` and `birdcl` static binaries.

```
./build.sh
```

#### Artifacts

This builds the following:

-  The `dist/bird` binary
-  The `dist/bird6` binary
-  The `dist/birdcl` binary

### 7. libnetwork-plugin (used in the calico/node image)

To build the libnetwork-plugin binaries, clone the libnetwork-plugin repo and checkout the correct tag.

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_LIBNETWORK_PLUGIN git@github.com:projectcalico/libnetwork-plugin.git
cd libnetwork-plugin
```

Build the `calico/libnetwork-plugin` container.

```
make clean
make calico/libnetwork-plugin
```

#### Artifacts

This builds the following:

-  The `calico/libnetwork-plugin` Docker image
-  The `dist/libnetwork-plugin` binary

### 8. calicoctl

To build the calicoctl binary, clone the calicoctl repo and checkout the correct tag

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_CALICOCTL git@github.com:projectcalico/calicoctl.git
cd calicoctl
```

Build the `calicoctl` binaries (available for different Linux, Mac and Windows) and the
`calico/ctl` container:

```
make clean
make ﻿dist/calicoctl dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe calico/ctl
```

#### Artifacts

This builds the following:

-  The `dist/calicoctl` binary
-  The `dist/calicoctl-darwin-amd64` binary
-  The `dist/calicoctl-windows-amd64.exe` binary
-  The `calico/ctl` container image


### 9. calico/node
To build the calico/node container, clone the node repo and
checkout the correct tag

```
cd $BASEDIR
git clone --depth 1 --single-branch --branch $VERSION_CALICO git@github.com:projectcalico/node.git
cd node
```

To build the calico/node image using the images built in the previous steps, start
by copying the various binaries into the working directory:

```
mkdir -p filesystem/bin
cp $BASEDIR/confd/bin/confd $BASEDIR/node/filesystem/bin/confd
cp $BASEDIR/bird/dist/* $BASEDIR/node/filesystem/bin
cp $BASEDIR/felix/bin/calico-felix $BASEDIR/node/filesystem/bin/calico-felix
cp $BASEDIR/calico-bgp-daemon/dist/* $BASEDIR/node/filesystsem/bin/
cp $BASEDIR/libnetwork-plugin/dist/libnetwork-plugin $BASEDIR/node/filesystsem/bin/libnetwork-plugin
```

Build the `calico/node` container:

```
make calico/node
docker tag calico/node calico/node:$VERSION_CALICO
```

#### Artifacts

This builds the following:

-  The `calico/node` container image
