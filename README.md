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
  calicoctl profile show [--detailed]
  calicoctl profile (add|remove) <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update
  calicoctl profile <PROFILE> member add <CONTAINER>
  calicoctl pool (add|remove) <CIDR> [--ipip]
  calicoctl pool show [--ipv4 | --ipv6]
  calicoctl bgppeer rr (add|remove) <IP>
  calicoctl bgppeer rr show [--ipv4 | --ipv6]
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER> [--force]
  calicoctl endpoint show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>] [--endpoint=<ENDPOINT_ID>] [--detailed]
  calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]  [--detailed] [<PROFILES>...]
  calicoctl endpoint <ENDPOINT_ID> profile show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]
  calicoctl reset
  calicoctl diags [--upload]
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
                          [default: calico/node:v0.4.5]
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.



```

## Can a guest container have multiple networked IP addresses?
Yes, using the `calicoctl container <CONTAINER> ip (add|remove) <IP>` command.

## How do I get network traffic into and out of my Calico cluster?
The recommended way to get traffic to/from your Calico network is by peering to 
your existing data center L3 routers using BGP and by assigning globally 
routable IPs (public IPs) to containers that need to be accessed from the internet. 
This allows incoming traffic to be routed directly to your containers without the 
need for NAT.  This flat L3 approach delivers exceptional network scalability
and performance.

Detailed datacenter networking recommendations are given in the main 
[Project Calico documentation](http://docs.projectcalico.org/en/latest/index.html).

### Enabling NAT for outgoing traffic from containers with private IP addresses
If you want to allow containers with private IP addresses to be able to access the 
internet then you can use your data center's existing outbound NAT capabilities
(typically provided by the data center's border routers).

Alternatively you can use Calico's built in outbound NAT capability by enabling it on any
Calico IP pool. In this case Calico will perform outbound NAT locally on the compute
node on which each container is hosted.
```
./calicoctl pool add <CIDR> --nat-outgoing
```
Where `<CIDR>` is the CIDR of your IP pool, for example `192.168.0.0/16`.

Remember: the security profile for the container will need to allow traffic to the internet as well.

### Enabling NAT for incoming traffic to containers with private IP addresses
As discussed already, the recommended way to get traffic to a containers that 
need to be accessed from the internet is to give them public IP addresses and
to configure Calico to peer with the data center's existing L3 routers.

In cases where this is not possible then you can configure incoming NAT 
(also known as DNAT) on your data centers existing border routers. Alternatively
you can configure incoming NAT with port mapping on the host on which the container
is running on. 
```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport <EXPOSED_PORT> -j DNAT  --to <CALICO_IP>:<SERVICE_PORT>
```
For example, you have a container that you've assigned the CALICO_IP of 192.168.7.4
to, and you have NGINX running on port 8000 inside the container. If you 
want to expose this on port 80, then you could run the following command:
```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 172.168.7.4:8000
```
The command will need to be run each time the host is restarted.

Remember: the security profile for the container will need to allow traffic to the exposed port as well.

### Evaluating Calico using IP in IP
If you are running in a public cloud that doesn't allow either L3 peering or L2 connectivity 
between Calico hosts then you can specify the `--ipip` flag your Calico IP pool:
```
./calicoctl pool add <CIDR> --ipip --nat-outgoing
```
Calico will then route traffic between Calico hosts using IP in IP.
