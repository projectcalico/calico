# Release

This is a tool using for building Calico components for internal and external releases.

## Getting started

```sh
make clean
make build
```

## Usage

```sh
./bin/release --help
```

## Developer Guide

### Building and publishing a test release

This section describes how to build a test release using the locally checked out code, and publish that release to your own GitHub repository and container registry.

### Building a local release

Build the release, providing your own registry to use for the images. For example:

```
ARCHES=amd64 ./bin/release hashrelease build --skip-validation --build-images --dev-registry <YOUR REGISTRY>
```

This may take some time, but will produce a full set of release images as well as an operator image based on the locally checked out commit. Artifacts can be found
in `_output/hashrelease`.

### Publishing the release

This section outlines how to publish a test release to your own image registry.

TODO
