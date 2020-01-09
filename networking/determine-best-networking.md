---
title: Determine best networking option
Description: Calico provides several networking implementations based on IP routing without the need for encapsulation. But encapsulation is supported when you need it.
---

### Big picture

{{site.prodname}} supports several container networking options for scalability, network performance, and interoperability with existing infrastructure.

### Value

Different network implementations are better suited to different environments. {{site.prodname}} provides several networking implementations based on IP routing without the need for encapsulation. If your deployment requires encapsulation, {{site.prodname}} provides overlay networking (IP in IP or VXLAN). {{site.prodname}} also supports enforcing policy with a number of other Kubernetes networking options. This document helps you choose the best networking option for your cluster.

### Concepts

#### About {{site.prodname}} networking

{{site.prodname}} provides a few ways to allow pods to connect to other pods, to the host, and to outside networks (for example, the internet).

{{site.prodname}} networking:

- Assigns IP addresses to pods using {{site.prodname}}’s IP address management (IPAM)
- Programs the local node’s routing table
- Distributes routes to other nodes and network devices

For details of {{site.prodname}} network design and architecture, see a lightboard presentation on the {{site.prodname}} dataplane, components, and how traffic is routed, [Calico network architecture and fundamentals](https://www.tigera.io/video/tigera-calico-fundamentals).

#### About BGP

{{site.prodname}} optionally supports using the Border Gateway Protocol (BGP) for sharing routing information into the network. {{site.prodname}} supports cloud deployments with full node-to-node mesh (with and without route reflectors), and on-premises deployments with **BGP peering** directly to Top of Rack (ToR) routers; allowing traffic to be routed directly to your workloads without needing NAT or encapsulation.

{{site.prodname}} can also use selective VXLAN encapsulation for workload traffic in cloud deployments without the need for BGP.

#### Other Kubernetes networking options

{{site.prodname}} can perform network policy enforcement with a number of other Kubernetes networking options.

##### Amazon AWS VPC CNI

The Amazon VPC CNI plugin uses AWS elastic network interfaces to provide pod networking. It is the default networking used in Amazon EKS, with {{site.prodname}} for [network policy enforcement]({{ site.baseurl }}/security/calico-network-policy).

##### Azure CNI

The Azure CNI plugin configures the Azure virtual network to provide pod networking. It is the default networking used in Microsoft AKS, with {{site.prodname}} for [network policy enforcement]({{ site.baseurl }}/security/calico-network-policy).

##### Flannel

Flannel routes pod traffic using static per-node CIDRs. It provides a number of networking backends. [Calico can be used for network policy enforcement]({{ site.baseurl }}/security/calico-network-policy).

##### Google cloud networking

Google cloud routes and [Alias IP ranges](https://cloud.google.com/vpc/docs/alias-ip) can be used to provide pod networking on Google cloud, and is the default for Google Kubernetes Engine (GKE), with {{site.prodname}} for [network policy enforcement]({{ site.baseurl }}/security/calico-network-policy).

#### Networking options

The table below shows common networking options when using {{site.prodname}}.

| **Networking Option**                                        | **Suitable Environments**                    | **Dataplane Performance and Visibility**                 | **Setup Complexity** | **Notes**                                                    |
| ------------------------------------------------------------ | -------------------------------------------- | -------------------------------------------------------- | -------------------- | ------------------------------------------------------------ |
| {{site.prodname}}, [Unencapsulated, peered with physical infrastructure](#unencapsulated-peered-with-physical-infrastructure) | On-prem                                      | Best                                                     | Moderate             | Allows pods to be directly accessed from outside the cluster |
| {{site.prodname}}, [Unencapsulated, not peered with physical infrastructure](#unencapsulated-not-peered-with-physical-infrastructure) | On-prem L2 networks, AWS, Azure      | Best                                                     | Low                  | IP in IP or VXLAN can be added for cross-subnet traffic      |
| {{site.prodname}}, [Encapsulated, IPIP](#ip-in-ip-or-vxlan-encapsulation)   | On-prem, most public clouds other than Azure | Good to excellent depending on NIC hardware capabilities | Low                  |                                                              |
| {{site.prodname}}, [Encapsulated, VXLAN](#ip-in-ip-or-vxlan-encapsulation)  | On-prem, any public cloud                    | Good to excellent depending on NIC hardware capabilities | Low                  |                                                              |
| AWS VPC CNI                                                  | Amazon EKS                                   | Excellent                                                | Low                  | Does not support full {{site.prodname}} IPAM feature set, limited to AWS. |
| Azure CNI                                                    | Microsoft AKS                                | Excellent                                                | Low                  | Does not support full {{site.prodname}} IPAM feature set, limited to Azure. |
| Google cloud                                                 | Google GKE                                   | Excellent                                                | Low                  | Does not support full {{site.prodname}} IPAM feature set, limited to GCP. |
| Flannel                                                      | Any public cloud                             | Poor to excellent, depending on chosen backend           | Medium               | Does not support full {{site.prodname}} IPAM feature set.                |


### Tutorial

This section provides more details on {{site.prodname}}’s built-in networking options:

- [Unencapsulated, peered with physical infrastructure](#unencapsulated-peered-with-physical-infrastructure)
- [Unencapsulated, not peered with physical infrastructure](#unencapsulated-not-peered-with-physical-infrastructure)
- [IP in IP or VXLAN encapsulation](#ip-in-ip-or-vxlan-encapsulation)

#### Unencapsulated, peered with physical infrastructure

{{site.prodname}} can peer with your routers using BGP. This provides great performance and easy debugging of unencapsulated traffic, and a wide range of options for network topology and connectivity. On top of the advantages of non-peered unencapsulated traffic:

- Your cluster can span multiple L2 subnets without needing encapsulation
- Resources outside your cluster can talk directly to your pods without NAT
- You can even expose pods directly to the internet if you want!

To configure BGP peering and determine the right topology, see [Configure BGP peering]({{ site.baseurl }}/networking/bgp). This option requires the ability to configure BGP peers on your routers.  If this is not an option, see the next section.

#### Unencapsulated, not peered with physical infrastructure

This option also provides near host-to-host levels of performance and allows the network direct visibility of traffic.

{{site.prodname}} can route pod traffic between nodes without encapsulation when all nodes are on a single L2 subnet, and if the underlying network doesn’t enforce IP address checks.  If your network consists of multiple L2 subnets then you can either [peer over BGP with your routers]({{ site.baseurl }}/networking/bgp), or use [cross-subnet encapsulation](#ip-in-ip-or-vxlan-encapsulation) to encapsulate only traffic that crosses subnet boundaries.

Traffic cannot be routed between pods and destinations that aren’t also in the {{site.prodname}} cluster without allowing workload access outside cluster, or peering with infrastructure.

> **Tip**: On AWS, you can disable source/destination checking to use this option within a VPC subnet. [Can I run Calico in a public cloud environment?]({{ site.baseurl }}/reference/faq#can-i-run-calico-in-a-public-cloud-environment).
{: .alert .alert-info}

#### IP in IP or VXLAN encapsulation

If possible, we recommend running {{site.prodname}} without network overlay/encapsulation. This provides the highest performance and simplest network; the packet that leaves your workload is the packet that goes on the wire.

However, selectively using overlays (IP in IP or VXLAN) can be useful when running on top of an underlying network that cannot easily be made aware of workload IPs. {{site.prodname}} can perform encapsulation on: all traffic, no traffic, or only on traffic that crosses a subnet boundary.

IP in IP or VXLAN encapsulation can also be used selectively between subnets -- this provides the performance benefits of unencapsulated traffic within subnets, for environments where the fabric contains multiple L2 networks and peering isn’t available. For example, if you are using {{site.prodname}} networking in AWS across multiple VPCs/subnets, {{site.prodname}} can selectively encapsulate only the traffic that is routed between the VPCs/subnets, and run without encapsulation within each VPC/subnet. For help, see [Overlay networking]({{ site.baseurl }}/networking/vxlan-ipip).

### Above and beyond

- [Configure BGP peering]({{ site.baseurl }}/networking/bgp)
- [Interoperate with legacy firewalls using IP ranges]({{ site.baseurl }}/networking/legacy-firewalls)
