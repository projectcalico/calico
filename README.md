<!--- master only -->
[![Build Status](https://semaphoreci.com/api/v1/calico/calicoctl/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/calicoctl)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calicoctl/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calicoctl/tree/master)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico for Containers

This repository is the home of `calico/node` and `calicoctl`.

<blockquote>
Note that the documentation in this repo is targeted at Calico contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>



For information on `calico/node`, see the [documentation on calico/node architecture](http://docs.projectcalico.org/master/reference/architecture/components).

For information on `calicoctl` usage, see the [calicoctl reference information](http://docs.projectcalico.org/master/reference/calicoctl/)

### Developing

Print useful actions with `make help`.

### Building `calico/node`

To build the `calico/node` container, run the following build step from
the root of the repository:

```
make calico/node
```

Use the build variables listed in the `Calico binaries` variable section
at the top of the Makefile to modify which components are included in the resulting image.
For example, the following command will produce a docker image called `calico/node:custom`
which uses custom Felix and Libnetwork binaries:

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
