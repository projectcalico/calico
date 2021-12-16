# Developer guide

This document describes how to set up a development environment for Calico, as well as how to build and test development code.

This guide is broken into the following main sections:

- [Building Calico from scratch](#building-calico-from-scratch)
- [Deploying your code on Kubernetes](#deploying-your-code-on-kubernetes)
- [Running automated tests](#running-automated-tests)

## Prerequisites:

These build instructions assume you have a Linux build environment
with:

-  Docker
-  git
-  make

## Checking out the code

Calico code is distributed across several different components, each of which lives in its own git repository (inside of projectcalico on github). To build *all* of Calico, you will need to check out each repository into a common base directory (for example, `$GOPATH/src/github.com/projectcalico`).

You will need the following repositories cloned on your development machine:

```
BASEDIR
└─── [calico](https://github.com/projectcalico/calico.git)
└─── [libcalico-go](https://github.com/projectcalico/libcalico-go.git)
└─── [confd](https://github.com/projectcalico/confd.git)
└─── [felix](https://github.com/projectcalico/felix.git)
└─── [typha](https://github.com/projectcalico/typha.git)
└─── [kube-controllers](https://github.com/projectcalico/kube-controllers.git)
└─── [calicoctl](https://github.com/projectcalico/calicoctl.git)
└─── [app-policy](https://github.com/projectcalico/app-policy.git)
└─── [pod2daemon](https://github.com/projectcalico/pod2daemon.git)
└─── [node](https://github.com/projectcalico/node.git)
└─── [cni-plugin](https://github.com/projectcalico/cni-plugin.git)
```

## Building Calico from scratch

### Building everything

Once the code for all subrepositories is checked out, try building it to make sure your development environment is configured properly. Run the following command from within the `calico` repository to build all container images from your locally checked out code.

#### Automated dev environment

Note: There is a `vagrant` recipe attempts to canonicalize instructions for a simple dev environment that is reproducible, see `hack/development-environment/` for details.  You can use it to quickly spin up a calico build and smoke test.

#### Manually create a dev environment (on Linux)

- First, build the images:
```
make dev-image REGISTRY=my-registry
```

This will build a all of the required `calico/` images, tagged by git commit hash, appended with the docker registry 'my-registry', i.e. 
```
REPOSITORY                            TAG                                     IMAGE ID            CREATED             SIZE
...
my-registry/cni-plugin                         v3.11.0-0.dev-3-g9755771-dirty-amd64    422e9c706bcd        2 hours ago         163MB
...
```


- Now, build the YAML manifests that are used to install calico:

```
make dev-manifests
```

The build uses the go package cache and local vendor caching to increase build speed. To perform a clean build, use the `dev-clean` target.

```
make dev-clean dev-image
```

### Building a single repository

Each repository can also be built on its own. The following are the standard `Makefile` targets that are in every project repository.

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
* `make ci`: run all CI steps for build and test, likely other targets. **WARNING:** It is **not** recommended to run `make ci` locally, as the actions it takes may be destructive.
* `make cd`: run all CD steps, normally pushing images out to registries. **WARNING:** It is **not** recommended to run `make cd` locally, as the actions it takes may be destructive, e.g. pushing out images. For your safety, it only will work if you run `make cd CONFIRM=true`, which only should be run by the proper CI system.

### Building Calico on Linux (s390x)

To build Calico and its components for Linux on IBM Z (s390x), follow the instructions provided [here](https://github.com/linux-on-ibm-z/docs/wiki/Building-Calico). 

## Deploying your code on Kubernetes

### Pushing container images

Once you have built local container images, you may want to push them to your container registry so they can be deployed
on a test cluster. You can do this using the `dev-push` target.

```
make dev-image dev-push REGISTRY=my-registry
```

### Generating Kubernetes manifests

To generate Kubernetes manifests which use your locally built development code, use the `dev-manifests` target.

```
make dev-manifests REGISTRY=my-registry
```

This will produce a set of manifests in `_output/dev-manifests` which are configured to use your locally built images.

## Running automated tests

### Running the unit tests

Each repository has its own set of automated tests that live in-tree and can be run without the need to deploy an end-to-end Kubernetes system. The easiest
way to run the tests is to submit a PR with your changes, which will trigger a build on the CI system.

If you'd like to run them locally we recommend running each repository's test suite individually,
since running the tests for the entire codebase can take a _very_ long time. Use the `test` target in a particular repository to run that
repository's tests.

```
make test
```

For information on how to run a subset of a repository's tests, refer to the documentation and Makefile in that repository.

If you really want to run all the tests across all repositories and are OK waiting a few hours, you can do so by running
the following command in the `calico` repo.

```
make dev-test
```

