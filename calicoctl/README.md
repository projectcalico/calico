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

### Install

Binary downloads of `calicoctl` can be found on the [Releases page].

Unpack the `calicoctl` binary and add it to your PATH and you are good to go!

If you want to use a package manager:

- [Homebrew] users can use `brew install calicoctl`.

[Releases page]: https://github.com/projectcalico/calicoctl/releases
[Homebrew]: https://brew.sh/

### Developing

Print useful actions with `make help`.

### Building `calicoctl`

For simplicity, `calicoctl` can be built in a Docker container, eliminating
the need for any dependencies in your host developer environment, using the following command:

```
make build
```

The binary will be put in `./bin/` and named `calicoctl-<os>-<arch>`, e.g.:

```
$ ls -1 ./bin/
calicoctl-linux-amd64
calicoctl-linux-arm64
calicoctl-linux-armv7
calicoctl-linux-ppc64le
calicoctl-linux-s390x
calicoctl-darwin-amd64
calicoctl-darwin-arm64
calicoctl-windows-amd64.exe
```

To build for a different OS or ARCH, simply define it as a var to `make`, e.g.:

```
$ make build ARCH=arm64
$ make build OS=darwin ARCH=amd64
```

To list all possible targets, run `make help`.

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
