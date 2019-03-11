[![Build Status](https://semaphoreci.com/api/v1/calico/calicoctl/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/calicoctl)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calicoctl/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calicoctl/tree/master)

[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# calicoctl

This repository is the home of `calicoctl`.

<blockquote>
Note that the documentation in this repo is targeted at Calico contributors.
<h1>Documentation for Calico users is here:<br><a href="https://docs.projectcalico.org">https://docs.projectcalico.org</a></h1>
</blockquote>


For information on `calicoctl` usage, see the [calicoctl reference information](http://docs.projectcalico.org/master/reference/calicoctl/)

### Developing

Print useful actions with `make help`.

### Building `calicoctl`

There are two ways to build calicoctl: natively, and dockerized

##### Dockerized Builds

For simplicity, `calicoctl` can be built in a Docker container, eliminating
the need for any dependencies in your host developer environment, using the following command:

```
make build
```

The binary will be put in `./dist/` and named `calicoctl-<os>-<arch>`, e.g.:

```
$ ls -1 ./dist/
calicoctl-linux-amd64
calicoctl-linux-arm64
calicoctl-linux-ppc64le
calicoctl-linux-s390x
calicoctl-darwin-amd64
calicoctl-windows-amd64.exe
```

To build for a different OS or ARCH, simply define it as a var to `make`, e.g.:

```
$ make build ARCH=arm64
$ make build OS=darwin ARCH=amd64
```

To list all possible targets, run `make help`.

##### Native Builds

1. Assuming you have already installed **go version 1.7.1+**,
   ensure you've cloned this repository into your Go project path.

   ```
   git clone https://github.com/projectcalico/calicoctl.git $GOPATH/src/github.com/projectcalico/calicoctl
   ```

1. [Install Glide](https://github.com/Masterminds/glide#install).

2. Populate the `vendor/` directory in the project's root with this project's dependencies:

   ```
   glide install -strip-vendor
   ```

3. Build the binary:
   ```
   make build
   ```

## Tests

Tests can be run in a container to ensure all build dependencies are met.

To run the tests
```
make test
```

**Note:** Tests depend on the test image `calico/test`, which is available only on `amd64`. The actual image used as set by the make variable `TEST_CONTAINER_NAME`. If you have a local build of that image or one for a different architecture, you can override it by setting the variable, e.g.:

```
$ make test TEST_CONTAINER_NAME=some/container:tag
```
