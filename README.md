<!--- master only -->
[![Build Status](https://semaphoreci.com/api/v1/calico/calico-containers/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/calico-containers)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-containers/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calico-containers/tree/master)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico for Containers

Calico provides a highly scalable networking solution for connecting data
center workloads (containers, VMs, or bare metal).  It is based on the same
scalable IP networking principles as the internet: providing connectivity using
a pure Layer 3 approach.  Calico can be deployed without encapsulation or
overlays to provide high performance at massive scales.

Read more about it on the [Project Calico website](https://www.projectcalico.org).

When using Calico networking in containerized environments, each container
gets its own IP and fine grain security policy.  A `calico-node` service runs
on each node which handles all of the necessary IP routing, installation of
policy rules, and distribution of routes across the cluster of nodes.

This repository contains:
-  The `calico/node` container Dockerfile and build environment.  It contains
  the configuration and "glue" that pull together four separate processes to
  provide Calico networking:
  * Felix, the Calico worker process
  * BIRD, the route distribution process
    (there are separate processes for IPv4 and IPv6)
  * Confd, a templating process to auto-generate configuration for BIRD
-  A command line tool, `calicoctl`, which makes it easy to configure
   and start the Calico service listed above, and allows you to interact with
   the datastore (etcd) to define and apply rich security policy to the
   containers you create.

Please refer to our [main documentation](http://docs.projectcalico.org) for details on deploying Calico and 
using `calicoctl`.

## Common set-up

Assuming you have already installed **go version 1.7.1+**, perform the following simple steps to get building:

- [Install Glide](https://github.com/Masterminds/glide#install)

- Clone this repository to your Go project path: 
```
git clone git@github.com:projectcalico/calico-containers.git $GOPATH/src/github.com/projectcalico/calico-containers
```

- Switch to your project directory:
```
cd $GOPATH/src/github.com/projectcalico/calico-containers
```

- Populate the `vendor/` directory in the project's root with this project's dependencies:
```
glide install
```

## Building calicoctl

### Non-release build
To do a quick, non-release build of calicoctl, suitable for local testing, run
```
make bin/calicoctl
```

The binary will be put in ./bin:
```
./bin/calicoctl --help
```

### Release build

For releases, we use a Docker-based build to ensure a clean environment with an appropriate glibc.  Specifically, we use a CentOS 6.6 container image to build against glibc v2.12.  this ensures compatibility with any later glibc.

To do a release build, run:
```
make release/calicoctl
```
The binary will be emitted to `./release/calicoctl-<version>`
