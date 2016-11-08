<!--- master only -->
[![Build Status](https://semaphoreci.com/api/v1/calico/calico-containers/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/calico-containers)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-containers/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calico-containers/tree/master)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico for Containers

This repository is the home of `calico/node` and `calicoctl`.

#### For information on how to get started using Calico see: https://docs.projectcalico.org

- For information on `calico/node`, see [documentation on calico/node architecture](http://docs.projectcalico.org/master/reference/architecture/components).

- For information on `calicoctl` usage, see [calicoctl reference information](http://docs.projectcalico.org/master/reference/calicoctl/)

### Developing

Calico-containers is a golang project, so assuming you have already installed **go version 1.7.1+**, clone this repository into your Go project path:

```
git clone https://github.com/projectcalico/calico-containers.git $GOPATH/src/github.com/projectcalico/calico-containers
```

Useful actions can be printed by running `make help` in the repo root.

### Building `calico/node`

To build the `calico/node` container, run the `make calico/node` build step from
the root of the repository.

Use the build variables listed in the `Calico binaries` variable section
at the top of the Makefile to modify which components are included in the resulting image.
For example, the following command will produce a docker image called `calico/node:custom`
which use custom Felix and Libnetwork binaries:
```
FELIX_CONTAINER_NAME=calico/felix:1.4.3 \
LIBNETWORK_PLUGIN_CONTAINER_NAME=calico/libnetwork-plugin:v1.0.0-beta \
BUILD_CONTAINER_NAME=calico/node:custom \
make calico/node
```

### Building `calicoctl`

There are two ways to build calicoctl: natively, and dockerized

##### Dockerized Builds

For simplicity, `calicoctl` can be built in a Docker container, eliminating
the need for any dependencies in your host developer environment, using the following command:

```
make dist/calicoctl
```

The binary will be put in `./dist`:

```
./dist/calicoctl --help
```

##### Native Builds

1. [Install Glide](https://github.com/Masterminds/glide#install).

2. Populate the `vendor/` directory in the project's root with this project's dependencies:
   ```
   glide install
   ```

3. Build the binary:
   ```
   make binary
   ```

## Tests

Calico-containers system tests run in a container to ensure all build dependencies are met.
Specifically, the `calico/test` image produced at https://github.com/projectcalico/libcalico
is used.

The following Makefile step will use that image to run all local tests:
```
make st
```
