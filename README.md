<!--- master only -->
[![Build Status](https://semaphoreci.com/api/v1/projects/9d7d365d-19cb-4699-8c84-b76da25ae271/473490/shields_badge.svg)](https://semaphoreci.com/calico/calico-docker--5)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-containers/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calico-containers/tree/master)
[![Coverage Status](https://coveralls.io/repos/projectcalico/calico-docker/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico-docker?branch=master)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

[![Slack Status](https://calicousers-slackin.herokuapp.com/badge.svg)](https://calicousers-slackin.herokuapp.com)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico for containers
Calico provides a highly scalable networking solution for connecting data 
center workloads (containers, VMs, or bare metal).  It is based on the same 
scalable IP networking principles as the internet: providing connectivity using
a pure Layer 3 approach.  Calico can be deployed without encapsulation or 
overlays to provide high performance at massive scales.

Read more about it on the [Project Calico website](http://www.projectcalico.org).

When using Calico networking in containerized environments, each container
gets its own IP and fine grain security policy.  A `calico-node` service runs
on each node which handles all of the necessary IP routing, installation of 
policy rules, and distribution of routes across the cluster of nodes.

This repository contains:
-  The `calico-node` container Dockerfile and build environment.  It contains
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
-  Documentation and getting started tutorials for various different deployment
   options.
-  Build, test and release frameworks.

Development is very active at the moment so please Star this project and check 
back often.

We welcome questions/comments/feedback (and pull requests).

* [Announcement Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-announce_lists.projectcalico.org)
* [Technical Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-tech_lists.projectcalico.org)
* [Slack Calico Users Channel](https://calicousers.slack.com) ([Sign up](https://calicousers-slackin.herokuapp.com))
* IRC - [#calico](https://kiwiirc.com/client/irc.freenode.net/#calico)
* For issues related to Calico in a containerized environment, please 
[raise issues](https://github.com/projectcalico/calico-containers/issues/new) on 
GitHub.

## Getting started

To get started using Calico, we recommend running through one or more of the 
available tutorials linked below.

These tutorials will help you understand the different environment options when 
using Calico.  In most cases we provide worked examples using manual setup on
your own servers, a quick set-up in a virtualized environment using Vagrant and
a number of cloud services.

- [Calico as a Docker network plugin](docs/calico-with-docker/docker-network-plugin/README.md)
- [Calico without Docker networking](docs/calico-with-docker/without-docker-networking/README.md)
- [Calico with rkt](docs/cni/rkt/README.md)
- [Calico with Kubernetes](docs/cni/kubernetes/README.md)
- [Calico with Mesos](https://github.com/projectcalico/calico-mesos-deployments)
- [Calico with Docker Swarm](docs/calico-with-docker/docker-network-plugin/CalicoSwarm.md)

## Further reading

You can read more about Calico networking in a containerized environment in
the material listed below.

  - **Learn how to configure Calico features in a deployment**
    - [`calicoctl` Reference Guide](docs/calicoctl.md) explains how the 
      `calicoctl` command line tool can be used to manage your Calico cluster
    - [Logging](docs/logging.md) describes how to set logging 
      levels and choose where Calico logs should be stored
    - [Advanced Network Policy](docs/AdvancedNetworkPolicy.md) describes how 
      to configure security policy between Calico endpoints and other networks
    - [BGP Configuration](docs/bgp.md) explains how to manage the BGP peering
      for integration of a Calico cluster in your network
    - [External Connectivity](docs/ExternalConnectivity.md) describes how to
      configure external connectivity for hosts on their own Layer 2 segment
    - [Running Calico Node Containers as a Service](docs/CalicoAsService.md)
      describes how to run the `calico/node` and `calico/node-libnetwork` images
      as system processes or services.  This guide includes example config for
      systemd services.
  - **Learn how Calico works under the covers**
    - [Anatomy of a calico-node container](docs/Components.md) to understand
      the key components that make up the `calico/node` service. 
    - [etcd Directory Structure](docs/etcdStructure.md) for viewing how Calico 
      stores data for network and endpoint configurations
    - [Lifecycle of a container](docs/DockerContainerLifecycle.md) 
      shows you what happens using Calico without Docker networking.
  - **Learn how to get involved with Calico builds and lower level integrations**
    - [Calico Repositories](docs/RepoStructure.md) to see the
      collection of Calico related respoitories that collectively provide the
      networking, tools, and orchestration integrations.
    - [Building and testing calico-containers images](docs/Building.md) to build a Calico setup on your local 
      machine for development and testing 
  - **FAQ and Troubleshooting**
    - [FAQ](docs/FAQ.md)
    - [Troubleshooting](docs/Troubleshooting.md)

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
