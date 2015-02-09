# Calico on docker
This project demonstrates Calico running in a Docker environment. If you do try using it, let us know how you get on by email (or just add a comment to the wiki).


## What it covers

Currently, this is a demonstration / proof of concept of Calico deployed in a Docker environment.

+ Calico services are containerized and available as pre-packaged images.
+ IP-networked Docker containers available via `docker run` or the standard Docker API.
+ Alongside the core services, we have packaged example code for taking advantage of Calico's security features.

## Getting started 

To get started follow the instruction here [Getting Started](docs/GettingStarted.md). It covers setting up a couple of CoreOS servers using Vagrant to use as docker hosts.

## How does it work?

Calico connects datacenter workloads (containers, VMs, or bare metal) via IP no matter which compute host they are on.  Read about it on the
[Project Calico website](http://www.projectcalico.org).  Endpoints are network interfaces associated with workloads.  In this demo we create one endpoint per container (but more than one is possible).

The `calico-master` container needs to run in one place in your cluster.  It keeps track of all workloads & endpoints and distributes information to `calico-node` containers that run on each Docker host you'll use with Calico.  If you have read the Calico architecture, the `calico-master` service instantiates both the 
+ ACL Manager component and the
+ Orchestrator Plugin component, backed by an [etcd](https://github.com/coreos/etcd) datastore.

The `calico-node` service is a worker that configures the network endpoints for containers, handles IP routing, and installs policy rules.  It includes
+ Felix, the Calico worker process,
+ BIRD, the routing process, and
+ a [Powerstrip](https://github.com/clusterhq/powerstrip) adapter to set up networking when Docker containers are created.

Finally, we provide a command line tool, `calicoctl`, which configures and starts the Calico services listed above, and allows you to interact with the Orchestrator Plugin to define and apply network & security policy to the containers you create.

The `calico-node` container exposes the Docker API on port 2375 using Powerstrip.  To start and stop containers, either point your Docker tools to this port, or set `DOCKER_HOST=localhost:2375` in your shell and use `docker`.
