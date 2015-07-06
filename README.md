[![Circle CI](https://circleci.com/gh/Metaswitch/calico-docker/tree/master.svg?style=svg)](https://circleci.com/gh/Metaswitch/calico-docker/tree/master)
# Calico on Docker
As well as providing networking for OpenStack VMs, Calico can provide networking for containers in a Docker environment.  Each container gets its own IP and fine grain security policy.  In addition, Calico can be deployed without encapsulation or overlays to provide high performance at massive scales.  For more information on Project Calico see http://www.projectcalico.org/learn/.

Development is very active at the moment so please Star this project and check back often.

We welcome questions/comments/feedback (and pull requests).

* Mailing List - http://lists.projectcalico.org/listinfo/calico
* IRC - [#calico](http://webchat.freenode.net?randomnick=1&channels=%23calico&uio=d4)
* For Calico-on-Docker specific issues, please [raise issues](https://github.com/Metaswitch/calico-docker/issues/new) on Github.

## Getting started

The recommended way to get started with Calico for the first time is to follow the [Getting Started Guide](docs/GettingStarted.md).  You can be up and running within a matter of minutes.  The guide includes step by step instructions covering
- setting up a 2 node Linux cluster either
  - using Vagrant (on Virtual Box or VMware) for easy setup on your laptop or other virtual environment
  - by manually setting up your own cluster
- setting up Calico on the cluster
- creating containers using Calico networking.

In addition to the [Getting Started Guide](docs/GettingStarted.md) we also have tutorials for:
- [Calico on Amazon](docs/AWS.md)
- [Calico on Google Compute Engine](docs/GCE.md)
- [Calico on DigitalOcean](docs/DigitalOcean.md)
- [Calico and Docker Swarm](docs/CalicoSwarm.md)

Finally, if you want to try out networking containers using Calico with Docker's new [libnetwork network driver support](https://github.com/docker/libnetwork) then you can try out our [Ubuntu Vagrant libnetwork example](https://github.com/Metaswitch/calico-ubuntu-vagrant).

## How does it work?

Calico connects datacenter workloads (containers, VMs, or bare metal) via IP no matter which compute host they are on.  Read about it on the [Project Calico website](http://www.projectcalico.org).  Endpoints are network interfaces associated with workloads.

Project Calico uses [etcd](https://github.com/coreos/etcd) to distribute information about workloads, endpoints, and policy to each Docker host.

The `calico-node` service is a worker that configures the network endpoints for containers, handles IP routing, and installs policy rules.  It runs in its own Docker container, and comprises
+ Felix, the Calico worker process
+ BIRD, the routing process
+ Experimental Docker [libnetwork](https://github.com/docker/libnetwork) to set up networking when Docker containers are created (this replaces the [Powerstrip](https://github.com/clusterhq/powerstrip) adapter).

We provide a command line tool, `calicoctl`, which makes it easy to configure and start the Calico services listed above, and allows you to interact with the etcd datastore to define and apply network and security policy to the containers you create. Using `calicoctl`, you can provision Calico nodes, endpoints, and define and manage a rich set of security policy. 

## FAQ 
For more information on what you can do with Calico, please visit the [frequently asked questions](docs/FAQ.md) page. 
