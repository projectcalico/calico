---
title: Frequently asked questions
description: Common questions that users ask about Calico.
canonical_url: '/reference/faq'
---

* TOC
{:toc}

## Why use {{site.prodname}}?

The problem {{site.prodname}} tries to solve is the networking of workloads (VMs,
containers, etc) in a high scale environment. Existing L2-based methods
for solving this problem have problems at high scale. Compared to these,
we think {{site.prodname}} is more scalable, simpler, and more flexible. We think
you should look into it if you have more than a handful of nodes on a
single site.

{{site.prodname}} also provides a rich network security model that
allows operators and developers to declare intent-based network security
policy that is automatically rendered into distributed firewall rules
across a cluster of containers, VMs, and/or servers.

For a more detailed discussion of this topic, see our blog post at
[Why Calico?](https://www.projectcalico.org/why-calico/){:target="_blank"}.

## Does {{site.prodname}} work with IPv6?

Yes! {{site.prodname}}'s core components support IPv6 out of the box. However,
not all orchestrators that we integrate with support IPv6 yet.

## Why does my container have a route to 169.254.1.1?

In a {{site.prodname}} network, each host acts as a gateway router for the
workloads that it hosts.  In container deployments, {{site.prodname}} uses
169.254.1.1 as the address for the {{site.prodname}} router.  By using a
link-local address, {{site.prodname}} saves precious IP addresses and avoids
burdening the user with configuring a suitable address.

While the routing table may look a little odd to someone who is used to
configuring LAN networking, using explicit routes rather than
subnet-local gateways is fairly common in WAN networking.

## Why isn't {{site.prodname}} working with a containerized Kubelet?

{{site.prodname}} hosted install places the necessary CNI binaries and config on each
Kubernetes node in a directory on the host as specified in the manifest.  By
default it places binaries in /opt/cni/bin and config /etc/cni/net.d.

When running the kubelet as a container using hyperkube as is common on CoreOS Container Linux,
you need to make sure that the containerized kubelet can see the CNI network
plugins and config that have been installed by mounting them into the kubelet container.

For example add the following arguments to the kubelet-wrapper service:

```
--volume /etc/cni/net.d:/etc/cni/net.d \
--volume /opt/cni/bin:/opt/cni/bin \
```

Without the above volume mounts, the kubelet will not call the {{site.prodname}} CNI binaries, and so
{{site.prodname}} [workload endpoints]({{ site.baseurl }}/reference/resources/workloadendpoint) will
not be created, and {{site.prodname}} policy will not be enforced.

## How do I view {{site.prodname}} CNI logs?

The {{site.prodname}} CNI plugin emits logs to stderr, which are then logged out by the kubelet.  Where these logs end up
depend on how your kubelet is configured.  For deployments using `systemd`, you can do this via `journalctl`.

The log level can be configured via the CNI network configuration file, by changing the value of the
key `log_level`.  See [Configuring the {{site.prodname}} CNI plugins]({{ site.baseurl }}/reference/cni-plugin/configuration) for more information.

CNI plugin logs can also be found in `/var/log/calico/cni`.

## How do I configure the pod IP range?

When using {{site.prodname}} IPAM, IP addresses are assigned from [IP Pools]({{ site.baseurl }}/reference/resources/ippool).

By default, all enabled IP pools are used. However, you can specify which IP pools to use for IP address management in the [CNI network config]({{ site.baseurl }}/reference/cni-plugin/configuration#ipam),
or on a per-pod basis using [Kubernetes annotations]({{ site.baseurl }}/reference/cni-plugin/configuration#using-kubernetes-annotations).

## How do I assign a specific IP address to a pod?

For most use cases it's not necessary to assign specific IP addresses to a Kubernetes pod and it's recommended to use Kubernetes services instead.
However, if you do need to assign a particular address to a pod, {{site.prodname}} provides two ways of doing this:

- You can request an IP that is available in {{site.prodname}} IPAM using the `cni.projectcalico.org/ipAddrs` annotation.
- You can request an IP using the `cni.projectcalico.org/ipAddrsNoIpam` annotation. Note that this annotation bypasses the configured IPAM plugin, and thus in most cases it is recommended to use the above annotation.

See the [Requesting a specific IP address]({{ site.baseurl }}/reference/cni-plugin/configuration#requesting-a-specific-ip-address) section in the CNI plugin reference documentation for more details.

## Why can't I see the 169.254.1.1 address mentioned above on my host?

{{site.prodname}} tries hard to avoid interfering with any other configuration
on the host.  Rather than adding the gateway address to the host side
of each workload interface, {{site.prodname}} sets the `proxy_arp` flag on the
interface.  This makes the host behave like a gateway, responding to
ARPs for 169.254.1.1 without having to actually allocate the IP address
to the interface.

## Why do all cali\* interfaces have the MAC address ee:ee:ee:ee:ee:ee?

In some setups the kernel is unable to generate a persistent MAC address and so
{{site.prodname}} assigns a MAC address itself. Since {{site.prodname}} uses
point-to-point routed interfaces, traffic does not reach the data link layer
so the MAC Address is never used and can therefore be the same for all the
cali\* interfaces.

## Can I prevent my Kubernetes pods from initiating outgoing connections?

Yes! The Kubernetes [`NetworkPolicy`](https://kubernetes.io/docs/concepts/services-networking/network-policies/){:target="_blank"}
API added support for egress policies in v1.8. You can also use `calicoctl`
to configure egress policy to prevent Kubernetes pods from initiating outgoing
connections based on the full set of supported {{site.prodname}} policy primitives
including labels, Kubernetes namespaces, CIDRs, and ports.

## I've heard {{site.prodname}} uses proxy ARP, doesn't proxy ARP cause a lot of problems?

It can, but not in the way that {{site.prodname}} uses it.

In container deployments, {{site.prodname}} only uses proxy ARP for resolving the
169.254.1.1 address.  The routing table inside the container ensures
that all traffic goes via the 169.254.1.1 gateway so that is the only
IP that will be ARPed by the container.

## Is {{site.prodname}} compliant with PCI/DSS requirements?

PCI certification applies to the whole end-to-end system, of which
{{site.prodname}} would be a part. We understand that most current solutions use
VLANs, but after studying the PCI requirements documents, we believe
that {{site.prodname}} does meet those requirements and that nothing in the
documents *mandates* the use of VLANs.

## How do I enable IP-in-IP and NAT outgoing on an IP pool?

1. Retrieve current IP pool config.

   ```bash
   calicoctl get ipPool --export -o yaml > pool.yaml
   ```

2. Modify IP pool config.

   Modify the pool's spec to enable IP-in-IP and NAT outgoing. (See
   [IP pools]({{ site.baseurl }}/reference/resources/ippool)
   for other settings that can be edited.)

   ```shell
   - apiVersion: projectcalico.org/v3
     kind: IPPool
     metadata:
      name: ippool-1
     spec:
       cidr: 192.168.0.0/16
       ipipMode: Always
       natOutgoing: true
   ```

3. Load the modified file.

   ```bash
   calicoctl replace -f pool.yaml
   ```

## How does {{site.prodname}} maintain saved state?

State is saved in a few places in a {{site.prodname}} deployment, depending on
whether it's global or local state.

Local state is state that belongs on a single compute host, associated
with a single running Felix instance (things like kernel routes, tap
devices etc.). Local state is entirely stored by the Linux kernel on the
host, with Felix storing it only as a temporary mirror. This makes Felix
effectively stateless, with the kernel acting as a backing data store on
one side and etcd as a data source on the other.

If Felix is restarted, it learns current local state by interrogating
the kernel at start up. It then reads from `etcd` all the local state
which it should have, and updates the kernel to match. This approach has
strong resiliency benefits, in that if Felix restarts you don't suddenly
lose access to your VMs or containers. As long as the Linux kernel is
running, you've still got full functionality.

The bulk of global state is mastered in whatever component hosts the
plugin.

-   In the case of OpenStack, this means a Neutron database. Our
    OpenStack plugin (more strictly a Neutron ML2 driver) queries the
    Neutron database to find out state about the entire deployment. That
    state is then reflected to `etcd` and so to Felix.
-   In certain cases, `etcd` itself contains the master copy of
    the data. This is because some Docker deployments have an `etcd`
    cluster that has the required resiliency characteristics, used to
    store all system configuration and so `etcd` is configured so as to
    be a suitable store for critical data.
-   In other orchestration systems, it may be stored in distributed
    databases, either owned directly by the plugin or by the
    orchestrator itself.

The only other state storage in a {{site.prodname}} network is in the BGP sessions,
which approximate a distributed database of routes. This BGP state is
simply a replicated copy of the per-host routes configured by Felix
based on the global state provided by the orchestrator.

This makes the {{site.prodname}} design very simple, because we store very little
state. All of our components can be shut down and restarted without risk,
because they resynchronize state as necessary. This makes modeling
their behavior extremely simple, reducing the complexity of bugs.

## I heard {{site.prodname}} is suggesting layer 2: I thought you were layer 3! What's happening?

It's important to distinguish what {{site.prodname}} provides to the workloads
hosted in a data center (a purely layer 3 network) with what the {{site.prodname}}
project *recommends* operators use to build their underlying network
fabric.

{{site.prodname}}'s core principle is that *applications* and *workloads*
overwhelmingly need only IP connectivity to communicate. For this reason
we build an IP-forwarded network to connect the tenant applications and
workloads to each other and the broader world.

However, the underlying physical fabric obviously needs to be set up
too. Here, {{site.prodname}} has discussed how both a layer 2 (see
[here]({{ site.baseurl }}/reference/architecture/design/l2-interconnect-fabric))
or a layer 3 (see
[here]({{ site.baseurl }}/reference/architecture/design/l3-interconnect-fabric))
fabric
could be integrated with {{site.prodname}}. This is one of the great strengths of
the {{site.prodname}} model: it allows the infrastructure to be decoupled from what
we show to the tenant applications and workloads.

We have some thoughts on different interconnect approaches (as noted
above), but just because we say that there are layer 2 and layer 3 ways
of building the fabric, and that those decisions may have an impact on
route scale, does not mean that {{site.prodname}} is "going back to Ethernet" or
that we're recommending layer 2 for tenant applications. In all cases we
forward on IP packets, no matter what architecture is used to build the
fabric.

## How do I control policy/connectivity without virtual/physical firewalls?

{{site.prodname}} provides an extremely rich security policy model, applying policy at the first and last hop
of the routed traffic within the {{site.prodname}} network (the source and
destination compute hosts).

This model is substantially more robust to failure than a centralized
firewall-based model. In particular, the {{site.prodname}} approach has no
single point of failure: if the device enforcing the firewall has failed
then so has one of the workloads involved in the traffic (because the
firewall is enforced by the compute host).

This model is also extremely amenable to scaling out. Because we have a
central repository of policy configuration, but apply it at the edges of
the network (the hosts) where it is needed, we automatically ensure that
the rules match the topology of the data center. This allows easy
scaling out, and gives us all the advantages of a single firewall (one
place to manage the rules), but none of the disadvantages (single points
of failure, state sharing, hairpinning of traffic, etc.).

Lastly, we decouple the reachability of nodes and the policy applied to
them. We use BGP to distribute the topology of the network, telling
every node how to get to every endpoint in case two endpoints need to
communicate. We use policy to decide *if* those two nodes should
communicate, and if so, how. If policy changes and two endpoints should
now communicate, where before they shouldn’t have, all we have to do is
update policy: the reachability information does not change. If later
they should be denied the ability to communicate, the policy is updated
again, and again the reachability doesn’t have to change.

## How does {{site.prodname}} interact with the Neutron API?

[{{site.prodname}}'s interpretation of Neutron API calls]({{ site.baseurl }}/networking/openstack/neutron-api)
goes into extensive detail about how various Neutron API calls translate into
{{site.prodname}} actions.

## Why isn't the `-p` flag on `docker run` working as expected?

The `-p` flag tells Docker to set up port mapping to connect a port on the
Docker host to a port on your container via the `docker0` bridge.

If a host's containers are connected to the `docker0` bridge interface, {{site.prodname}}
would be unable to enforce security rules between workloads on the same host;
all containers on the bridge would be able to communicate with one other.

You can securely configure port mapping by following [External connectivity]({{ site.baseurl }}/networking/external-connectivity).

## Can {{site.prodname}} containers use any IP address within a pool, even subnet network/broadcast addresses?

Yes! {{site.prodname}} is fully routed, so all IP address within a {{site.prodname}} pool are usable as
private IP addresses to assign to a workload.  This means addresses commonly
reserved in a L2 subnet, such as IPv4 addresses ending in .0 or .255, are perfectly
okay to use.

## How do I get network traffic into and out of my {{site.prodname}} cluster?

The recommended way to get traffic to/from your {{site.prodname}} network is by peering to
your existing data center L3 routers using BGP and by assigning globally
routable IPs (public IPs) to containers that need to be accessed from the internet.
This allows incoming traffic to be routed directly to your containers without the
need for NAT.  This flat L3 approach delivers exceptional network scalability
and performance.

A common scenario is for your container hosts to be on their own
isolated layer 2 network, like a rack in your server room or an entire data
center.  Access to that network is via a router, which also is the default
router for all the container hosts.

If this describes your infrastructure,
[External connectivity]({{ site.baseurl }}/networking/external-connectivity) explains in more detail
what to do. Otherwise, if you have a layer 3 (IP) fabric, then there are
detailed datacenter networking recommendations given
in [{{site.prodname}} over IP fabrics]({{ site.baseurl }}/reference/architecture/design/l3-interconnect-fabric).
We'd also encourage you to [get in touch](https://www.projectcalico.org/contact/){:target="_blank"}
to discuss your environment.

### How can I enable NAT for outgoing traffic from containers with private IP addresses?

If you want to allow containers with private IP addresses to be able to access the
internet then you can use your data center's existing outbound NAT capabilities
(typically provided by the data center's border routers).

Alternatively you can use {{site.prodname}}'s built in outbound NAT capability by enabling it on any
{{site.prodname}} IP pool. In this case {{site.prodname}} will perform outbound NAT locally on the compute
node on which each container is hosted.

```bash
cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-1
spec:
  cidr: <CIDR>
  natOutgoing: true
EOF
```

Where `<CIDR>` is the CIDR of your IP pool, for example `192.168.0.0/16`.

Remember: the security profile for the container will need to allow traffic to the
internet as well.  Refer to the appropriate guide for your orchestration
system for details on how to configure policy.

### How can I enable NAT for incoming traffic to containers with private IP addresses?

As discussed, the recommended way to get traffic to containers that
need to be accessed from the internet is to give them public IP addresses and
to configure {{site.prodname}} to peer with the data center's existing L3 routers.

In cases where this is not possible then you can configure incoming NAT
(also known as DNAT) on your data centers existing border routers. Alternatively
you can configure incoming NAT with port mapping on the host on which the container
is running on.

1. Create a new chain called `expose-ports` to hold the NAT rules.

   ```bash
   iptables -t nat -N expose-ports
   ```

1. Jump to that chain from the `OUTPUT` and `PREROUTING` chains.

   ```bash
   iptables -t nat -A OUTPUT -j expose-ports
   iptables -t nat -A PREROUTING -j expose-ports
   ```

   > **Tip**: The `OUTPUT` chain is hit by traffic originating on the host itself;
   > the `PREROUTING` chain is hit by traffic coming from elsewhere.
   {: .alert .alert-success}

1. For each port you want to expose, add a rule to the
   expose-ports chain, replacing `<PUBLIC_IP>` with the host IP that you
   want to use to expose the port and `<PUBLIC_PORT>` with the host port.

   ```bash
   iptables -t nat -A expose-ports -p tcp --destination <PUBLIC_IP> \
   --dport <PUBLIC_PORT> -j DNAT  --to <CALICO_IP>:<SERVICE_PORT>
   ```

For example, you have a container to which you've assigned the `CALICO_IP`
of 192.168.7.4, and you have NGINX running on port 8080 inside the container.
If you want to expose this service on port 80 and your host has IP 192.0.2.1,
then you could run the following commands:

```bash
iptables -t nat -N expose-ports
iptables -t nat -A OUTPUT -j expose-ports
iptables -t nat -A PREROUTING -j expose-ports

iptables -t nat -A expose-ports -p tcp --destination 192.0.2.1 --dport 80 -j DNAT --to 192.168.7.4:8080
```
{: .alert .alert-success}

The commands will need to be run each time the host is restarted.

Remember: the security profile for the container will need to allow traffic to the exposed port as well.
Refer to the appropriate guide for your orchestration system for details on how to configure policy.

### Can I run {{site.prodname}} in a public cloud environment?

Yes. If you are running in a public cloud that doesn't allow either L3 peering or L2 connectivity between {{site.prodname}} hosts then you can enable IP-in-IP in your {{site.prodname}} IP pool:

```bash
cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-1
spec:
  cidr: <CIDR>
  ipipMode: Always
  natOutgoing: true
EOF
```

{{site.prodname}} will then route traffic between {{site.prodname}} hosts using IP-in-IP.

For best performance in AWS, you can disable [Source/Destination Check]({{ site.baseurl }}/reference/resources/felixconfig#spec) instead of using IP-in-IP or VXLAN; but only if all your instances are in the same subnet of your VPC. The setting must be `Disable` for the EC2 instance(s) to process traffic not matching the host interface IP address. This is also applicable if your cluster is spread across multiple subnets. If your cluster traffic crosses subnets, set `ipipMode` (or `vxlanMode`) to `CrossSubnet` to reduce the encapsulation overhead. Check [configuring overlay networking]({{ site.baseurl }}/networking/vxlan-ipip) for the details.

You can disable Source/Destination Check using [Felix configuration]({{ site.baseurl }}/reference/resources/felixconfig), the AWS CLI, or the EC2 console. For example, using the AWS CLI:

```bash
aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --source-dest-check "{\"Value\": false}"

cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-2
spec:
  cidr: <CIDR>
  natOutgoing: true
EOF
```

### On AWS with IP-in-IP, why do I see no connectivity between workloads or only see connectivity if I ping in both directions?

By default, AWS security groups block incoming IP-in-IP traffic.

However, if an instance has recently sent some IP-in-IP traffic out when it receives some incoming IP-in-IP traffic,
then AWS sees that as a response to an outgoing connection and it allows the incoming traffic.  This leads to some very
confusing behavior where traffic can be blocked and then suddenly start working!

To resolve the issue, add a rule to your security groups that allows inbound and outbound IP-in-IP traffic (IP protocol
number 4) between your hosts.

## In Calico for OpenStack, why can't a VM ping its default gateway?

The concept of default gateway makes sense with OpenStack networking drivers that simulate
direct layer 2 (Ethernet) connectivity between VMs in the same Neutron network.  With that
kind of simulation,

-  When a VM sends to another VM in the same network, there is no routing at all, from the
   VM point of view. (Of course there may be routing in the underlay network, because
   compute hosts may be on different subnets.)

-  When a VM sends to something outside its own network, it goes - by simulated layer 2 -
   to the default gateway first, and then is routed to wherever it is addressed to.

However OpenStack also allows drivers, including Calico, that use routing between the VMs
of a Neutron network.  With Calico specifically, any packet sent by a VM is
layer-2-terminated and IP-routed by the VM's compute host, whether the VM is sending to
another VM in the same network, or to anywhere else. So Calico doesn't need the "default
gateway" concept, and it doesn't really make any sense with Calico. If a VM thinks that
"my default gateway is the first hop at which the packets I send can be IP-routed", and in
any way relies on that, that will be wrong, with Calico networking.

Now, with all that said, for detailed technical reasons to do with the DHCP server
(dnsmasq), Calico does actually configure the default gateway IP - i.e. bind it to a Linux
network interface - on every compute host with at least one VM in the relevant Neutron
network; and that is one of the ingredients needed, in Linux, for a VM to be able to ping
that IP.

The reason why it still *isn't* possible for a VM to ping that IP, is that Calico by
default configures iptables rules to block almost all communication *to* its own host -
because in general, of course, a workload should not be able to access and possibly
compromise its host. There are a few pinholes here, e.g. for DHCP, but those do not
include ping (ICMP Echo). If you start running a command like `watch 'sudo iptables-save
-c | grep DROP'` on a compute host, and then try pinging the default gateway IP from a VM
on that host, you will see the DROP count increasing as each ping packet is sent and
blocked.

This behaviour is controlled by a config parameter named DefaultEndpointToHostAction,
whose default is DROP. For the sake of demonstration, you can change this by adding
`DefaultEndpointToHostAction = RETURN` to `/etc/calico/felix.cfg`, then use `sudo
systemctl restart calico-felix` to restart Felix, and then you will observe that a VM on
that host *can* ping its default gateway. However we do not recommend routinely operating
with `DefaultEndpointToHostAction = RETURN`, because that potentially allows a malicious
VM to compromise its host.

In summary, then, there are two points behind why a VM cannot normally ping its default
gateway, with Calico.

1.  The default gateway concept just doesn't really fit, and isn't needed, given how
    Calico routes everything at the compute node - which is a fundamental aspect of Calico
    networking for OpenStack.

1.  Calico's iptables rules generally do not allow a VM to contact its host.

## Are the Calico manifests compatible with CoreOS?

As it stands, the majority of the provided manifests are compatible with CoreOS systems. The
only required change is as follows:

As `/usr` on CoreOS is readonly, the default path of the `flexvol-driver-host` volume will
need to be changed to match the path of the `--flex-volume-plugin-dir` flag passed to the
`kube-controller-manager`.

For example:
```yaml
- name: flexvol-driver-host
    hostPath:
      type: DirectoryOrCreate
      path: /var/lib/kubelet/volumeplugins/nodeagent~uds
```

## Can Calico do IP multicast?

Calico is a routed L3 network where each pod gets a /32.  There's no broadcast domain for pods.
That means that multicast doesn't just work as a side effect of broadcast.  To get multicast to
work, the host needs to act as a multicast gateway of some kind.  Calico's architecture was designed
to extend to cover that case but it's not part of the product as yet.
