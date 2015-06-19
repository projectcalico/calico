# Frequently Asked Questions
This page contains answers to some frequently-asked questions about Calico on Docker.

## Can a guest container have multiple networked IP addresses?
Yes. You can add IP addresses using the `calicoctl container <CONTAINER> ip (add|remove) <IP>` command.

## How do I get network traffic into and out of my Calico cluster?
The recommended way to get traffic to/from your Calico network is by peering to 
your existing data center L3 routers using BGP and by assigning globally 
routable IPs (public IPs) to containers that need to be accessed from the internet. 
This allows incoming traffic to be routed directly to your containers without the 
need for NAT.  This flat L3 approach delivers exceptional network scalability
and performance.

Detailed datacenter networking recommendations are given in the main 
[Project Calico documentation](http://docs.projectcalico.org/en/latest/index.html).

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

Remember: the security profile for the container will need to allow traffic to the internet as well. You can read about how to configure security profiles in the [Advanced Network Policy](AdvancedNetworkPolicy.md) guide.

### How can I enable NAT for incoming traffic to containers with private IP addresses?
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
For example, you have a container to which you've assigned the CALICO_IP of 192.168.7.4, and you have NGINX running on port 80 inside the container. If you want to expose this service on port 80, then you could run the following command:
```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 172.168.7.4:80
```
The command will need to be run each time the host is restarted.

Remember: the security profile for the container will need to allow traffic to the exposed port as well.  You can read about how to configure security profiles in the [Advanced Network Policy](AdvancedNetworkPolicy.md) guide.

### Can I run Calico in a public cloud environment? 
Yes.  If you are running in a public cloud that doesn't allow either L3 peering or L2 connectivity between Calico hosts then you can specify the `--ipip` flag your Calico IP pool:
```
./calicoctl pool add <CIDR> --ipip --nat-outgoing
```
Calico will then route traffic between Calico hosts using IP in IP.

## Orchestrator integration

For a lower level integration see [Orchestrators](Orchestrators.md).

