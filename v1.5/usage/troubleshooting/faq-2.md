---
title: Frequently Asked Questions
canonical_url: 'https://docs.projectcalico.org/v3.6/usage/troubleshooting/faq'
---


This page contains answers to some frequently-asked questions about Calico on Docker.

## Can a guest container have multiple networked IP addresses?
Yes. You can add IP addresses using the `calicoctl container <CONTAINER> ip (add|remove) <IP>` command.

## Why isn't the `-p` flag on `docker run` working as expected?
The `-p` flag tells Docker to set up port mapping to connect a port on the
Docker host to a port on your container via the `docker0` bridge.

If a host's containers are connected to the `docker0` bridge interface, Calico
would be unable to enforce security rules between workloads on the same host;
all containers on the bridge would be able to communicate with one other.

You can securely configure port mapping by following our [guide on Exposing
Container Ports to the Internet]({{site.baseurl}}/{{page.version}}/usage/external-connectivity).

## Can Calico containers use any IP address within a pool, even subnet network/broadcast addresses?

Yes!  Calico is fully routed, so all IP address within a Calico pool are usable as
private IP addresses to assign to a workload.  This means addresses commonly
reserved in a L2 subnet, such as IPv4 addresses ending in .0 or .255, are perfectly
okay to use.

## How do I get network traffic into and out of my Calico cluster?
The recommended way to get traffic to/from your Calico network is by peering to
your existing data center L3 routers using BGP and by assigning globally
routable IPs (public IPs) to containers that need to be accessed from the internet.
This allows incoming traffic to be routed directly to your containers without the
need for NAT.  This flat L3 approach delivers exceptional network scalability
and performance.

A common scenario is for your container hosts to be on their own
isolated layer 2 network, like a rack in your server room or an entire data
center.  Access to that network is via a router, which also is the default
router for all the container hosts.

If this describes your infrastructure, the
[External Connectivity tutorial]({{site.baseurl}}/{{page.version}}/usage/external-connectivity) explains in more detail
what to do. Otherwise, if you have a layer 3 (IP) fabric, then there are
detailed datacenter networking recommendations given
in the main [this article]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric).
We'd also encourage you to [get in touch](https://www.projectcalico.org/contact/)
to discuss your environment.

### How can I enable NAT for outgoing traffic from containers with private IP addresses?
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

Remember: the security profile for the container will need to allow traffic to the
internet as well. You can read about how to configure security profiles in the
[Advanced Network Policy tutorial]({{site.baseurl}}/{{page.version}}/usage/configuration/advanced-network-policy).

### How can I enable NAT for incoming traffic to containers with private IP addresses?
As discussed, the recommended way to get traffic to containers that
need to be accessed from the internet is to give them public IP addresses and
to configure Calico to peer with the data center's existing L3 routers.

In cases where this is not possible then you can configure incoming NAT
(also known as DNAT) on your data centers existing border routers. Alternatively
you can configure incoming NAT with port mapping on the host on which the container
is running on.
```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport <EXPOSED_PORT> -j DNAT  --to <CALICO_IP>:<SERVICE_PORT>
```
For example, you have a container to which you've assigned the CALICO_IP of 192.168.7.4, and you have NGINX running on port 80 inside the container. If you want to expose this service on port 80, then you could run the following command:
```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 172.168.7.4:80
```
The command will need to be run each time the host is restarted.

Remember: the security profile for the container will need to allow traffic to the exposed port as well.  You can read about how to configure security profiles in the [Advanced Network Policy]({{site.baseurl}}/{{page.version}}/usage/configuration/advanced-network-policy) guide.

### Can I run Calico in a public cloud environment?
Yes.  If you are running in a public cloud that doesn't allow either L3 peering or L2 connectivity between Calico hosts then you can specify the `--ipip` flag your Calico IP pool:

```shell
./calicoctl pool add <CIDR> --ipip --nat-outgoing
```
Calico will then route traffic between Calico hosts using IP in IP.

In AWS, you disable `Source/Dest. Check` instead of using IP in IP as long as all your instances are in the same subnet of your VPC.  This will provide the best performance.  You can disable this with the CLI, or right click the instance in the EC2 console, and `Change Source/Dest. Check` from the `Networking` submenu.

```shell
aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --source-dest-check "{\"Value\": false}"
...
./calicoctl pool add <CIDR> --nat-outgoing
```

### Why IP of container/host is unreachable from host/container with Calico IPAM?
Reason may be complex. A simple one is that ARP packets are ignored by host. Try checking sysctl net.ipv4.conf.all.arp_ignore, which should be 0 for calico.
