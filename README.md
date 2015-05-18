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

## How can I get network traffic into and out of my Calico cluster?
The ideal way to get traffic to/from your Calico network is by peering to 
your existing data center routers using BGP and by assigning globally 
routable IPs to your workloads. This avoids the need for NATs, 
tunnels or overlays. 

Detailed datacenter networking recommendations are given in the main 
[Project Calico documentation](http://docs.projectcalico.org/en/latest/index.html).

In some cases however, it's not possible to set up such a peering. In such a
 case, then iptables rules can be configured on the compute hosts to get 
 traffic into and out of the Calico networked containers.

### Egress traffic from containers
If you just want to be able to access the internet from your containers and 
they only have private Calico IP addresses then you can configure SNAT on 
each compute host.
```
iptables -t nat -A POSTROUTING -s 192.168.0.0/16 ! -d 192.168.0.0/16 -j 
MASQUERADE
```

This configures masquerading for all traffic from the default Calico subnet 
that's destined for outside that subnet. You'll need to use a different IP 
range (or multiple IP ranges) if you've configured different pools. 

The command will need to be run each time the host is restarted.

### Ingress traffic to containers
if you're trying to host a public facing service on your Calico network then
you'll want some way of exposing that service. It's highly desirable that 
you assign a public IP to your container and peer with your border router 
so that traffic for that IP is brought to the appropriate compute host. If 
you can't do this and you're host already has a public facing IP, then you 
can use port mapping to get the traffic into the container.

You will need to runt he following commands to on the host that the container
is running on.

```
iptables -A FORWARD -p tcp -d <CALICO_IP> --dport <SERVICE_PORT> -j ACCEPT
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport <EXPOSED_PORT> -j DNAT  --to <CALICO_IP>:<SERVICE_PORT>
```

For example, you have a container that you've assigned the CALICO_IP of 192.168.7.4
to, and you have NGINX running on port 8000 inside the container. If you 
want to expose this on port 80, then you could run the following two commands:

```
iptables -A FORWARD -p tcp -d 192.168.7.4 --dport 8000 -j ACCEPT
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 172.168.7.4:8000
```
The command will need to be run each time the host is restarted.
