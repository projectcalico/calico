# Calico on docker
Calico can provide networking in a Docker environment. Each container gets it's own IP, there is no ecapsulation and it can support massive scale. For more details see http://www.projectcalico.org/technical/

Development is very active at the moment so please Star this project and check back often.

We welcome questions/comment/feedback (and pull requests)
* Mailing List - http://lists.projectcalico.org/listinfo/calico
* IRC - [#calico](http://webchat.freenode.net?randomnick=1&channels=%23calico&uio=d4)
* For Calico-on-Docker specific issues, please [raise issues](https://github.com/Metaswitch/calico-docker/issues/new) on Github.

## Getting started 

To get started follow the instruction here [Getting Started](docs/GettingStarted.md). It covers setting up a couple of CoreOS servers using Vagrant to use as docker hosts.

## Orchestrator intregration

For a lower level integration see [Orchestrators](docs/Orchestrators.md). 

## What it covers
+ The Calico components run Docker containers
+ Calico can provide network connectivity with security policy enforcement to Docker containers.

+ IP-networked Docker containers available via `docker run` or the standard Docker API. We utilizate the excellent [Powerstrip](https://github.com/clusterhq/powerstrip) project to make this seamless
+ Alongside the core services, we provide a simple commandline tool `calicoctl` for managing Calico.



## How does it work?

Calico connects datacenter workloads (containers, VMs, or bare metal) via IP no matter which compute host they are on.  Read about it on the
[Project Calico website](http://www.projectcalico.org).  Endpoints are network interfaces associated with workloads.  Using calicoctl we currently only support one endpoint per container, but more than one is possible if you use the lower level APIs.

The `calico-master` container needs to run in one place in your cluster.  It keeps track of all workloads & endpoints and distributes information to `calico-node` containers that run on each Docker host you'll use with Calico.  If you have read the Calico architecture, the `calico-master` service instantiates both the 
+ ACL Manager component and the
+ Orchestrator Plugin component, backed by an [etcd](https://github.com/coreos/etcd) datastore.

The `calico-node` service is a worker that configures the network endpoints for containers, handles IP routing, and installs policy rules.  It includes
+ Felix, the Calico worker process,
+ BIRD, the routing process, and
+ a [Powerstrip](https://github.com/clusterhq/powerstrip) adapter to set up networking when Docker containers are created.

Finally, we provide a command line tool, `calicoctl`, which configures and starts the Calico services listed above, and allows you to interact with the Orchestrator Plugin to define and apply network & security policy to the containers you create.

```
Usage:
  calicoctl master --ip=<IP>
                   [--etcd=<ETCD_AUTHORITY>]
                   [--master-image=<DOCKER_IMAGE_NAME>]
  calicoctl node --ip=<IP>
                 [--etcd=<ETCD_AUTHORITY>]
                 [--node-image=<DOCKER_IMAGE_NAME>]
  calicoctl status [--etcd=<ETCD_AUTHORITY>]
  calicoctl reset [--etcd=<ETCD_AUTHORITY>]
  calicoctl version [--etcd=<ETCD_AUTHORITY>]
  calicoctl addgroup <GROUP>  [--etcd=<ETCD_AUTHORITY>]
  calicoctl addtogroup <CONTAINER_ID> <GROUP>
                       [--etcd=<ETCD_AUTHORITY>]
  calicoctl diags
  calicoctl status
  calicoctl reset
Options:
 --ip=<IP>                The local management address to use.
 --etcd=<ETCD_AUTHORITY>  The location of the etcd service as
                          host:port [default: 127.0.0.1:4001]
 --master-image=<DOCKER_IMAGE_NAME>  Docker image to use for
                          Calico's master container
                          [default: calico/master:v0.0.6]
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:v0.0.6]

```
