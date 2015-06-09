[![Circle CI](https://circleci.com/gh/Metaswitch/calico-docker/tree/master.svg?style=svg)](https://circleci.com/gh/Metaswitch/calico-docker/tree/master)
# Calico on Docker
Calico can provide networking in a Docker environment. Each container gets its own IP, there is no encapsulation and it can support massive scale. For more information on Project Calico see http://www.projectcalico.org/learn/

Development is very active at the moment so please Star this project and check back often.

We welcome questions/comment/feedback (and pull requests).

* Mailing List - http://lists.projectcalico.org/listinfo/calico
* IRC - [#calico](http://webchat.freenode.net?randomnick=1&channels=%23calico&uio=d4)
* For Calico-on-Docker specific issues, please [raise issues](https://github.com/Metaswitch/calico-docker/issues/new) on Github.

## Getting started

To get started follow the instruction here [Getting Started](docs/GettingStarted.md). They set up two CoreOS servers using Vagrant, and run Calico components in containers to provide networking between other guest containers.

To build your own binaries, read [Building Binaries](docs/Building.md).

## Orchestrator integration

For a lower level integration see [Orchestrators](docs/Orchestrators.md).

## What it covers
+ The Calico components run in Docker containers.
+ Calico provides network connectivity with security policy enforcement for other Docker containers.
+ IP-networked Docker containers available via `docker run` or the standard Docker API. We use the excellent [Powerstrip](https://github.com/clusterhq/powerstrip) project to make this seamless.
+ Alongside the core services, we provide a simple commandline tool `calicoctl` for managing Calico.


## How does it work?

Calico connects datacenter workloads (containers, VMs, or bare metal) via IP no matter which compute host they are on.  Read about it on the [Project Calico website](http://www.projectcalico.org).  Endpoints are network interfaces associated with workloads.

Project Calico uses [etcd](https://github.com/coreos/etcd) to distribute information about workloads, endpoints, and policy to each Docker host.

The `calico-node` service is a worker that configures the network endpoints for containers, handles IP routing, and installs policy rules.  It comprises
+ Felix, the Calico worker process
+ BIRD, the routing process
+ a [Powerstrip](https://github.com/clusterhq/powerstrip) adapter to set up networking when Docker containers are created.

We provide a command line tool, `calicoctl`, which makes it easy to configure and start the Calico services listed above, and allows you to interact with the etcd datastore to define and apply network and security policy to the containers you create.

```
Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:4001]

Usage:
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>]
  calicoctl node stop [--force]
  calicoctl status
  calicoctl shownodes [--detailed]
  calicoctl profile show [--detailed]
  calicoctl profile (add|remove) <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update
  calicoctl profile <PROFILE> member add <CONTAINER>
  calicoctl pool (add|remove) <CIDR>
  calicoctl pool show [--ipv4 | --ipv6]
  calicoctl bgppeer rr (add|remove) <IP>
  calicoctl bgppeer rr show [--ipv4 | --ipv6]
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER> [--force]
  calicoctl reset
  calicoctl diags
  calicoctl checksystem [--fix]
  calicoctl restart-docker-with-alternative-unix-socket
  calicoctl restart-docker-without-alternative-unix-socket

Options:
 --interface=<INTERFACE>  The name to give to the interface in the container
                          [default: eth1]
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:latest]
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.



```

## Can a guest container have multiple networked IP addresses?
Yes, using the `calicoctl container <CONTAINER> ip (add|remove) <IP>` command.

