<!--- master only -->
[![Build Status](https://semaphoreci.com/api/v1/projects/9d7d365d-19cb-4699-8c84-b76da25ae271/473490/shields_badge.svg)](https://semaphoreci.com/calico/calico-docker--5)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-docker/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calico-docker/tree/master)
[![Coverage Status](https://coveralls.io/repos/projectcalico/calico-docker/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico-docker?branch=master)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

[![Slack Status](https://calicousers-slackin.herokuapp.com/badge.svg)](https://calicousers-slackin.herokuapp.com)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico on Docker
As well as providing networking for OpenStack VMs, Calico can provide
networking for containers in a Docker environment.  Each container gets its 
own IP and fine grain security policy.  In addition, Calico can be deployed 
without encapsulation or overlays to provide high performance at massive 
scales.  For more information on Project Calico see 
http://www.projectcalico.org/learn/.

Development is very active at the moment so please Star this project and check 
back often.

We welcome questions/comments/feedback (and pull requests).

* [Announcement Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-announce_lists.projectcalico.org)
* [Technical Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-tech_lists.projectcalico.org)
* [Slack Calico Users Channel](https://calicousers.slack.com) ([Sign up](https://calicousers-slackin.herokuapp.com))
* IRC - [#calico](https://kiwiirc.com/client/irc.freenode.net/#calico)
* For Calico-on-Docker specific issues, please [raise issues][raise-issues] on 
GitHub.

## How does it work?

Calico provides a highly scalable networking solution for connecting data 
center workloads (containers, VMs, or bare metal).  It is based on the same 
scalable IP networking principles as the internet, providing connectivity using
standard IP routing and isolation between workloads (or other fine grained
policy) using iptables programmed at the source and destination workloads.

Read more about it on the [Project Calico website][project-calico].

Project Calico uses [etcd][etcd] to distribute information about workloads, 
endpoints (a specific networking interface associated with a workload),
and policy to each Docker host.

The `calico-node` service is a worker that configures the network endpoints 
for containers, handles IP routing, and installs policy rules.  It runs in its 
own Docker container, and comprises
- Felix, the Calico worker process
- BIRD, the route distribution process

We provide a command line tool, `calicoctl`, which makes it easy to configure 
and start the Calico services listed above, and allows you to interact with 
the etcd datastore to define and apply network and security policy to the 
containers you create. Using `calicoctl`, you can provision Calico nodes, 
endpoints, and define and manage a rich set of security policy. 

## Getting Started

To get started using, we recommend running through one or more of the available 
[demonstrations](#demonstrations) described below.

If you would like to get involved writing code for calico-docker, or if you 
need to build binaries specific to your OS, checkout out the 
[Building and testing guide](docs/Building.md).

### Demonstrations

Worked examples are available for demonstrating Calico networking with the 
following different networking options:

- [Demonstration with Docker default networking](docs/getting-started/default-networking/Demonstration.md)
- [Demonstration with libnetwork](docs/getting-started/libnetwork/Demonstration.md)

See the [Networking options](#networking-options) below for more details on 
each of these different networking options.

With each of these tutorials we provide details for running the demonstration 
using manual setup on your own servers, or with a quick set-up in a virtualized
environment using Vagrant, or a number of cloud services.

We also provide the following additional demonstration: 
- [Calico and Kubernetes](docs/kubernetes/README.md)
- [Calico and Mesos](docs/mesos/README.md)


### Networking options

#### Docker default networking

This uses Docker's standard networking infrastructure, requiring you to 
explicitly add a created container into a Calico network.

This is compatible with all Docker versions from 1.6 onwards.

#### Docker with libnetwork

Docker's native [libnetwork network driver][libnetwork] is available in the 
Docker 1.9 release currently undergoing development.

Setup of the libnetwork environment is a little more involved since it requires
the current master (1.9.dev) builds of Docker, and the use of etcd as a
datastore for Docker clustering.

## FAQ 
For more information on what you can do with Calico, please visit the 
[frequently asked questions](docs/FAQ.md) page. 


[libnetwork]: https://github.com/docker/libnetwork
[raise-issues]: https://github.com/projectcalico/calico-docker/issues/new
[project-calico]: http://www.projectcalico.org
[etcd]: https://github.com/coreos/etcd
