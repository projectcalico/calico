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

1. First, make sure that you have generates manifest versions - the release tool expects that manifests use valid semantic versions for image tags.

   Update manifests to use the new release branch instead of master.  Update versions in the following files:

   - charts/calico/values.yaml
   - charts/tigera-operator/values.yaml

   Then, run manifest generation

   ```
   make generate
   ```

1. Build the release, providing your own registry to use for the images.

   ```

   ```
