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
Usage:
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>] [--force-unix-socket]
  calicoctl node stop [--force]
  calicoctl status
  calicoctl shownodes [--detailed]
  calicoctl profile show [--detailed]
  calicoctl profile add <PROFILE>
  calicoctl profile remove <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag add <TAG>
  calicoctl profile <PROFILE> tag remove <TAG>
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update
  calicoctl profile <PROFILE> member add <CONTAINER>
  calicoctl ipv4 pool add <CIDR>
  calicoctl ipv4 pool del <CIDR>
  calicoctl ipv4 pool show
  calicoctl ipv6 pool add <CIDR>
  calicoctl ipv6 pool del <CIDR>
  calicoctl ipv6 pool show
  calicoctl container add <CONTAINER> <IP>
  calicoctl container remove <CONTAINER> [--force]
  calicoctl reset
  calicoctl diags

Options:
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:latest]


```

## Building the calicoctl binary
The calicoctl binary is a statically-compiled version of the calicoctl.py script in this directory.  To (re)build it run:

```
./create-binary.sh
```

## Can a guest container have multiple networked IP addresses?

Using `calicoctl` we currently only support one IP address per container, but more than one is possible if you use the lower level APIs.
