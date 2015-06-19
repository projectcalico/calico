[![Circle CI](https://circleci.com/gh/Metaswitch/calico-docker/tree/master.svg?style=svg)](https://circleci.com/gh/Metaswitch/calico-docker/tree/master)
# Calico on Docker
Calico can provide networking in a Docker environment. Each container gets its own IP, there is no encapsulation and it can support massive scale. For more information on Project Calico see http://www.projectcalico.org/learn/

Development is very active at the moment so please Star this project and check back often.

We welcome questions/comment/feedback (and pull requests).

* Mailing List - http://lists.projectcalico.org/listinfo/calico
* IRC - [#calico](http://webchat.freenode.net?randomnick=1&channels=%23calico&uio=d4)
* For Calico-on-Docker specific issues, please [raise issues](https://github.com/Metaswitch/calico-docker/issues/new) on Github.

## Getting started

The best way to get started using Calico is with one of the tutorials listed below.
- [Getting started with Calico](docs/GettingStarted.md): Set up two CoreOS servers and run Calico to provide networking between guest containers.
- [Calico on Amazon AWS](docs/AWS.md): Run Calico networked containers on AWS, and expose a simple web service.
- [Calico on Google Compute Engine](docs/GCE.md): Run Calico networked containers on GCE, and expose a simple web service.
- [Calico on Digital Ocean]: Run Calico networked containers on DO, and expose a simple web service.
- [Calico and Docker Swarm](docs/CalicoSwarm.md): Run Calico networked containers on a Docker Swarm cluster.

To build your own binaries, read [Building Binaries](docs/Building.md).

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
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>] [--as=<AS_NUM>]
  calicoctl node stop [--force]
  calicoctl node bgppeer add <PEER_IP> as <AS_NUM>
  calicoctl node bgppeer remove <PEER_IP>
  calicoctl node bgppeer show [--ipv4 | --ipv6]
  calicoctl status
  calicoctl profile show [--detailed]
  calicoctl profile (add|remove) <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule add (inbound|outbound) [--at=<POSITION>]
    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [<SRCCIDR>])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [<DSTCIDR>])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [<SRCCIDR>])]
           [(to   [(tag <DSTTAG>)] [<DSTCIDR>])] |
      [(from [(tag <SRCTAG>)] [<SRCCIDR>])]
      [(to   [(tag <DSTTAG>)] [<DSTCIDR>])]
    )]
  calicoctl profile <PROFILE> rule remove (inbound|outbound) (--at=<POSITION>|
    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [<SRCCIDR>])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [<DSTCIDR>])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [<SRCCIDR>])]
           [(to   [(tag <DSTTAG>)] [<DSTCIDR>])] |
      [(from [(tag <SRCTAG>)] [<SRCCIDR>])]
      [(to   [(tag <DSTTAG>)] [<DSTCIDR>])]
    )])
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update
  calicoctl profile <PROFILE> member add <CONTAINER>
  calicoctl pool (add|remove) <CIDR> [--ipip] [--nat-outgoing]
  calicoctl pool show [--ipv4 | --ipv6]
  calicoctl default-node-as [<AS_NUM>]
  calicoctl bgppeer add <PEER_IP> as <AS_NUM>
  calicoctl bgppeer remove <PEER_IP>
  calicoctl bgppeer show [--ipv4 | --ipv6]
  calicoctl bgp-node-mesh [on|off]
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container <CONTAINER> endpoint-id show
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER> [--force]
  calicoctl endpoint show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>] [--endpoint=<ENDPOINT_ID>] [--detailed]
  calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>] [<PROFILES>...]
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
                          [default: calico/node:latest]
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.
 --host=<HOSTNAME>        Filters endpoints on a specific host.
 --orchestrator=<ORCHESTRATOR_ID>    Filters endpoints created on a specific orchestrator.
 --workload=<WORKLOAD_ID> Filters endpoints on a specific workload.
 --endpoint=<ENDPOINT_ID> Filters endpoints with a specific endpoint ID.
 --as=<AS_NUM>            The AS number to assign to the node.


```


## More Information
For more information on what you can do with Calico, please visit the [frequently asked questions](docs/FAQ.md) page. 
