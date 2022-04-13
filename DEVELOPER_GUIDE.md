# Developer guide

This document describes how to set up a development environment for Calico, as well as how to build and test development code.

This guide is broken into the following main sections:

- [Building Calico from scratch](#building-calico-from-scratch)
- [Deploying your code on Kubernetes](#deploying-your-code-on-kubernetes)
- [Running automated tests](#running-automated-tests)

Additional developer docs can be found in [hack/docs](hack/docs).

## Prerequisites:

These build instructions assume you have a Linux build environment
with:

-  Docker
-  git
-  make

## Building Calico 

### Building all of Calico

To build all of Calico, run the following command from the root of the repository.

```
make image DEV_REGISTRY=my-registry
```

This will produce several docker-images, each tagged with the registry provided.

### Build a specific image

To build just one image, you can run the same command in a particular sub-directory.

For example, to build `calico/node`, run the following:

```
make -C node image
```

### Building a specific architecture

By default, images will be produced for the build machine's architecture. To cross-compile, pass the `ARCH` environment variable. For example, to
build for arm64, run the following:

```
make image ARCH=arm64
```

- Now, build the YAML manifests that are used to install calico:

```
make dev-manifests
```

The build uses the go package cache and local vendor caching to increase build speed. To perform a clean build, use the `dev-clean` target.

```
make dev-clean dev-image
```

### Makefile target reference

The following are the standard `Makefile` targets that are in every project directory.

* `make build`: build the binary for the current architecture. Normally will be in `bin/` or `dist/` and named `NAME-ARCH`, e.g. `felix-arm64` or `typha-amd64`. If there are multiple OSes available, then named `NAME-OS-ARCH`, e.g. `calicoctl-darwin-amd64`.
* `make build ARCH=<ARCH>`: build the binary for the given `ARCH`. Output binary will be in `bin/` or `dist/` and follows the naming convention listed above.
* `make build-all`: build binaries for all supported architectures. Output binaries will be in `bin/` or `dist/` and follow the naming convention listed above.
* `make image`: create a docker image for the current architecture. It will be named `NAME:latest-ARCH`, e.g. `calico/felix:latest-amd64` or `calico/typha:latest-s390x`. If multiple operating systems are available, will be named `NAME:latest-OS-ARCH`, e.g. `calico/ctl:latest-linux-ppc64le`
* `make image ARCH=<ARCH>`: create a docker image for the given `ARCH`. Images will be named according to the convention listed above.
* `make image-all`: create docker images for all supported architectures. Images will be named according to the convention listed above in `make image`.
* `make test`: run all tests
* `make ci`: run all CI steps for build and test, likely other targets. **WARNING:** It is **not** recommended to run `make ci` locally, as the actions it takes may be destructive.
* `make cd`: run all CD steps, normally pushing images out to registries. **WARNING:** It is **not** recommended to run `make cd` locally, as the actions it takes may be destructive, e.g. pushing out images. For your safety, it only will work if you run `make cd CONFIRM=true`, which only should be run by the proper CI system.

## Running automated tests

### Running the unit tests

Each directory has its own set of automated tests that live in-tree and can be run without the need to deploy an end-to-end Kubernetes system. The easiest
way to run the tests is to submit a PR with your changes, which will trigger a build on the CI system.

If you'd like to run them locally we recommend running each directory's test suite individually,
since running the tests for the entire codebase can take a _very_ long time. Use the `test` target in a particular directory to run that
directory's tests.

```
make test
```

For information on how to run a subset of a directory's tests, refer to the documentation and Makefile in that directory.
