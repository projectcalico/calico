---
title: Determine best networking option
description: Learn about the different networking options Calico supports so you can choose the best option for your needs.
---

### Big picture

Learn about the different networking options {{site.prodname}} supports so you can choose the best option for your needs.

### Value

{{site.prodname}}’s flexible modular architecture supports a wide range of deployment options, so you can select the best networking approach for your specific environment and needs. This includes the ability to run with a variety of CNI and IPAM plugins, and underlying network types, in non-overlay or overlay modes, with or without BGP.

### Concepts

If you want to fully understand the network choices available to you, we recommend you make sure you are familiar with and understand the following concepts.  If you would prefer to skip the learning and get straight to the choices and recommendations, you can jump ahead to [Networking Options](#networking-options).

#### Kubernetes networking basics
The Kubernetes network model defines a “flat” network in which:
- Every pod get its own IP address.
- Pods on any node can communicate with all pods on all other nodes without NAT.

This creates a clean, backwards-compatible model where pods can be treated much like VMs or physical hosts from the perspectives of port allocation, naming, service discovery, load balancing, application configuration, and migration.  Network segmentation can be defined using network policies to restrict traffic within these base networking capabilities.

Within this model there’s quite a lot of flexibility for supporting different networking approaches and environments.  The details of exactly how the network is implemented depend on the combination of CNI, network, and cloud provider plugins being used.

#### CNI plugins
CNI (Container Network Interface) is a standard API which allows different network implementations to plug into Kubernetes. Kubernetes calls the API any time a pod is being created or destroyed.  There are two types of CNI plugins:
- CNI network plugins: responsible for adding or deleting pods to/from the Kubernetes pod network. This includes creating/deleting each pod’s network interface and connecting/disconnecting it to the rest of the network implementation.
- CNI IPAM plugins: responsible for allocating and releasing IP addresses for pods as they are created or deleted. Depending on the plugin, this may include allocating one or more ranges of IP addresses (CIDRs) to each node, or obtaining IP addresses from an underlying public cloud’s network to allocate to pods.

#### Cloud provider integrations
Kubernetes cloud provider integrations are cloud-specific controllers that can configure the underlying cloud network to help provide Kubernetes networking.  Depending on the cloud provider, this could include automatically programming routes into the underlying cloud network so it knows natively how to route pod traffic.

#### Kubenet
Kubenet is an extremely basic network plugin built into Kubernetes. It does not implement cross-node networking or network policy. It is typically used together with a cloud provider integration that sets up routes in the cloud provider network for communication between nodes, or in single node environments. Kubenet is not compatible with {{site.prodname}}.

#### Overlay networks
An overlay network is a network that is layered on top of another network.  In the context of Kubernetes, an overlay network can be used to handle pod-to-pod traffic between nodes on top of an underlying network that is not aware of pod IP addresses or which pods are running on which nodes. Overlay networks work by encapsulating network packets that an underlying network doesn’t know how to handle (for example using pod IP addresses) within an outer packet which the underlying network does know how to handle (for example node IP addresses). Two common network protocols used for encapsulation are VXLAN and IP-in-IP.

The main advantage of using an overlay network is that it reduces dependencies on the underlying network.  For example, you can run a VXLAN overlay on top of almost any underlying network, without needing to integrate with or make any changes to the underlying network.

The main disadvantages of using an overlay network are:
- A slight performance impact. The process of encapsulating packets takes a small amount of CPU, and the extra bytes required in the packet to encode the encapsulation (VXLAN or IP-in-IP headers) reduces the maximum size of inner packet that can be sent, which in turn can mean needing to send more packets for the same amount of total data.
- The pod IP addresses are not routable outside of the cluster.  More on this below! 

#### Cross-subnet overlays
In addition to standard VXLAN or IP-in-IP overlays, {{site.prodname}} also supports “cross-subnet” modes for VXLAN and IP-in-IP.  In this mode, within each subnet, the underlying network acts as an L2 network. Packets sent within a single subnet are not encapsulated, so you get the performance of a non-overlay network.  Packets sent across subnets are encapsulated, like a normal overlay network, reducing dependencies on the underlying network (without the need to integrate with or make any changes to the underlying network).

Just like with a standard overlay network, the underlying network is not aware of pod IP addresses and the pod IP addresses are not routable outside of the cluster.

#### Pod IP routability outside of the cluster
An important distinguishing feature of different Kubernetes network implementations is whether or not pod IP addresses are routable outside of the cluster across the broader network.

**Not routable**

If the pod IP addresses are not routable outside of the cluster then when a pod tries to establish a network connection to an IP address that is outside of the cluster, Kubernetes uses a technique called SNAT (Source Network Address Translation) to change the source IP address from the IP address of the pod, to the IP address of the node hosting the pod.  Any return packets on the connection get automatically mapped back to the pod IP address.  So the pod is unaware the SNAT is happening, the destination for the connection sees the node as the source of the connection, and the underlying broader network never sees pod IP addresses.

For connections in the opposite direction, where something outside of the cluster needs to connect to a pod, this can only be done via Kubernetes services or Kubernetes ingress. Nothing outside of the cluster can directly connect to a pod IP address, because the broader network doesn’t know how to route packets to pod IP addresses.

**Routable**

If the pod IP addresses are routable outside of the cluster then pods can connect to the outside world without SNAT, and the outside world can connect directly to pods without going via a Kubernetes service or Kubernetes ingress.

The advantage of pod IP addresses that are routable outside the cluster are:
- Avoiding SNAT for outbound connections may be essential for integrating with existing broader security requirements.  It can also simplify debugging and understandability of operation logs.
- If you have specialized workloads that mean some pods need to be directly accessible without going via Kubernetes services or Kubernetes ingress, then routable pod IPs can be operationally simpler than the alternative of using host networked pods.

The main disadvantage of pod IP addresses that are routable outside the cluster is that the pod IPs must be unique across the broader network.  So for example, if running multiple clusters you will need to use a different IP address range (CIDR) for pods in each cluster.  This in turn can lead to IP address range exhaustion challenges when running at scale, or if there are other significant existing enterprise demands on IP address space.

**What determines routability?**

If you are using an overlay network for your cluster, then pod IPs are not normally routable outside of the cluster.

If you aren’t using an overlay network, then whether pod IPs are routable outside of the cluster depends on what combination of CNI plugins, cloud provider integrations, or (for on-prem) BGP peering with the physical network, is being used.

#### BGP
BGP (Border Gateway Protocol) is a standards based networking protocol for sharing routes across a network.  It’s one of the fundamental building blocks of the internet, with exceptional scaling characteristics.

{{site.prodname}} has built in support for BGP.  In an on-prem deployment, this allows {{site.prodname}} to peer with the physical network (typically to Top of Rack routers) to exchange routes, making a non-overlay network where pod IP addresses routable across the broader network, just like any other workload attached to the network.

### About {{site.prodname}} Networking
{{site.prodname}}’s flexible modular architecture for networking includes the following.

**{{site.prodname}} CNI network plugin**

The {{site.prodname}} CNI network plugin connects pods to the host network namespace’s L3 routing using a pair of virtual ethernet devices (veth pair). This L3 architecture avoids the unnecessary complexity and performance overheads of additional L2 bridges that feature in many other Kubernetes networking solutions.

**{{site.prodname}} CNI IPAM plugin**

The {{site.prodname}} CNI IPAM plugin allocates IP addresses for pods out of one or more configurable IP address ranges, dynamically allocating small blocks of IPs per node as required.  The result is a more efficient IP address space usage compared to many other CNI IPAM plugins, including the host local IPAM plugin which is used in many networking solutions.

**Overlay network modes**

{{site.prodname}} can provide both VXLAN or IP-in-IP overlay networks, including cross-subnet only modes.

**Non-overlay network modes**

{{site.prodname}} can provide non-overlay networks running on top of any underlying L2 network, or an L3 network that is either a public cloud network with appropriate cloud provider integration, or a BGP capable network (typically an on-prem network with standard Top-of-Rack routers).

**Network policy enforcement**

{{site.prodname}}’s network policy enforcement engine implements the full range of Kubernetes Network Policy features, plus the extended features of {{site.prodname}} Network Policy.  This works in conjunction with {{site.prodname}}’s built in networking modes, or any other {{site.prodname}} compatible network plugins and cloud provider integrations.

### {{site.prodname}} compatible CNI plugins and cloud provider integrations
In addition to the {{site.prodname}} CNI plugins and built in networking modes, {{site.prodname}} is also compatible with a number of third party CNI plugins and cloud provider integrations.

**Amazon VPC CNI**

The Amazon VPC CNI plugin allocates pod IPs from the underlying AWS VPC and uses AWS elastic network interfaces to provide VPC native pod networking (pod IPs that are routable outside of the cluster). It is the default networking used in {% include open-new-window.html text='Amazon EKS' url='https://aws.amazon.com/eks/' %}, with Calico for network policy enforcement.

**Azure CNI**

The Azure CNI plugin allocates pod IPs from the underlying Azure VNET configures the Azure virtual network to provide VNET native pod networking (pod IPs that are routable outside of the cluster). It is the default networking used in {% include open-new-window.html text='Microsoft AKS' url='https://azure.microsoft.com/en-us/services/kubernetes-service/' %}, with Calico for network policy enforcement.

**Azure cloud provider**

The Azure cloud provider integration can be used as an alternative to the Azure CNI plugin. It uses the host-local IPAM CNI plugin to allocate pod IPs, and programs the underlying Azure VNET subnet with corresponding routes. Pod IPs are only routable within the VNET subnet (which often equates to meaning they are not routable outside of the cluster).

**Google cloud provider**

The Google cloud provider integration uses host-local IPAM CNI plugin to allocate pod IPs, and programs the Google cloud network Alias IP ranges to provide VPC native pod networking on Google cloud (pod IPs that are routable outside of the cluster). It is the default for Google Kubernetes Engine (GKE), with Calico for network policy enforcement.

**Host local IPAM**

The host local CNI IPAM plugin is a commonly used IP address management CNI plugin, which allocates a fixed size IP address range (CIDR) to each node, and then allocates pod IP addresses from within that range.  The default address range size is 256 IP addresses (a /24), though two of those IP addresses are reserved for special purposes and not assigned to pods. The simplicity of host local CNI IPAM plugin makes it easy to understand, but results in less efficient IP address space usage compared to {{site.prodname}} CNI IPAM plugin.

**Flannel**

Flannel routes pod traffic using static per-node CIDRs obtained from the host-local IPAM CNI plugin. Flannel provides a number of networking backends, but is predominantly used with its VXLAN overlay backend. {{site.prodname}} CNI and {{site.prodname}} network policy can be combined with flannel and the host-local IPAM plugin to provide a VXLAN network with policy enforcement.  This combination is sometimes referred to as “Canal”.  

>**Note**: {{site.prodname}} now has built in support for VXLAN, which we generally recommend for simplicity in preference to using the Calico+Flannel combination.
{: .alert .alert-info}

### Networking Options

#### On-prem
The most common network setup for {{site.prodname}} on-prem is non-overlay mode using [BGP to peer]({{ site.baseurl }}/networking/bgp) with the physical network (typically top of rack routers) to make pod IPs routable outside of the cluster.  (You can of course configure the rest of your on-prem network to limit the scope of pod IP routing outside of the cluster if desired.)  This setup provides a rich range of advanced {{site.prodname}} features, including the ability to advertise Kubernetes service IPs (cluster IPs or external IPs), and the ability to control IP address management at the pod, namespace, or node level, to support a wide range of possibilities for integrating with existing enterprise network and security requirements.

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:No,Routing:BGP' %}

If peering BGP to the physical network is not an option, you can also run non-overlay mode if the cluster is within a single L2 network, with Calico just peering BGP between the nodes in the cluster.  Even though this is not strictly an overlay network, the pod IPs are not routable outside of the cluster, because the broader network does not have routes for the pod IPs.

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:No,Routing:BGP' %}

Alternatively you can run {{site.prodname}} in either VXLAN or IP-in-IP overlay mode, with cross-subnet overlay mode to optimize performance within each L2 subnet.

*Recommended:*

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:VXLAN,Routing:Calico' %}

*Alternative:*

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:IPIP,Routing:BGP' %}

#### AWS
If you would like pod IP addresses to be routable outside of the cluster then you must use the Amazon VPC CNI plugin. This is the default networking mode for {% include open-new-window.html text='EKS' url='https://aws.amazon.com/eks/' %}, with Calico for network policy.  Pod IP addresses are allocated from the underlying VPC and the maximum number of pods per node is dependent on the {% include open-new-window.html text='instance type' url='https://github.com/aws/amazon-vpc-cni-k8s#eni-allocation' %}.

{% include geek-details.html details='Policy:Calico,IPAM:AWS,CNI:AWS,Overlay:No,Routing:VPC Native' %}

If you prefer to avoid dependencies on a specific cloud provider, or allocating pod IPs from the underlying VPC is problematic due to IP address range exhaustion challenges, or if the maximum number of pods supported per node by the Amazon VPC CNI plugin is not sufficient for your needs, we recommend using {{site.prodname}} networking in cross-subnet overlay mode. Pod IPs will not be routable outside of the cluster, but you can scale the cluster up to the limits of Kubernetes with no dependencies on the underlying cloud network.

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:VXLAN,Routing:Calico' %}

You can learn more about Kubernetes Networking on AWS, including how each of the above options works under the covers, in this short video: {% include open-new-window.html text='Everything you need to know about Kubernetes networking on AWS' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/' %}.

#### Azure
If you would like pod IP addresses to be routable outside of the cluster then you must use the Azure CNI plugin. This is supported by {% include open-new-window.html text='AKS' url='https://azure.microsoft.com/en-us/services/kubernetes-service/' %}, with Calico for network policy.  Pod IP addresses are allocated from the underlying VNET.

{% include geek-details.html details='Policy:Calico,IPAM:Azure,CNI:Azure,Overlay:No,Routing:VPC Native' %}

If you want to use AKS but allocating pod IPs from the underlying VNET is problematic due to IP address range exhaustion challenges, you can use {{site.prodname}} in conjunction with the Azure cloud provider integration. This uses host-local IPAM to allocate /24 per node, and programs routes within the cluster’s underlying VNET subnet for those /24.  Pod IPs are not routable outside of the cluster / VNET subnet, so the same pod IP address range (CIDR) can be used across multiple clusters if desired. 

>**Note**: This is referred to as kubenet + Calico in some AKS docs, but it is actually Calico CNI with Azure cloud provider, and does not use the kubenet plugin.
{: .alert .alert-info}

{% include geek-details.html details='Policy:Calico,IPAM:Host Local,CNI:Calico,Overlay:No,Routing:VPC Native' %}

If you aren’t using AKS, and prefer to avoid dependencies on a specific cloud provider or allocating pod IPs from the underlying VNET is problematic due to IP address range exhaustion challenges, we recommend using {{site.prodname}} networking in cross-subnet overlay mode. Pod IPs will not be routable outside of the cluster, but you can scale the cluster up to the limits of Kubernetes with no dependencies on the underlying cloud network.

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:VXLAN,Routing:Calico' %}

You can learn more about Kubernetes Networking on Azure, including how each of the above options works under the covers, in this short video: {% include open-new-window.html text='Everything you need to know about Kubernetes networking on Azure' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-azure/' %}.

#### Google Cloud
If you would like pod IP addresses to be routable outside of the cluster then you must use the Google cloud provider integration in conjunction with host-local IPAM CNI plugin. This is supported by {% include open-new-window.html text='GKE' url='https://cloud.google.com/kubernetes-engine' %}, with Calico for network policy.  Pod IP addresses are allocated from the underlying VPC, and corresponding Alias IP addresses are automatically assigned to nodes.

{% include geek-details.html details='Policy:Calico,IPAM:Host Local,CNI:Calico,Overlay:No,Routing:VPC Native' %}

If you prefer to avoid dependencies on a specific cloud provider, or allocating pod IPs from the underlying VPC is problematic due to IP address range exhaustion challenges, we recommend using {{site.prodname}} networking in overlay mode. As Google cloud network is a pure L3 network, cross-subnet mode is not supported.  Pod IPs will not be routable outside of the cluster, but you can scale the cluster up to the limits of Kubernetes with no dependencies on the underlying cloud network.

*Recommended:*

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico' %}

*Alternative:*

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP' %}

You can learn more about Kubernetes Networking on Google cloud, including how each of the above options works under the covers, in this short video: {% include open-new-window.html text='Everything you need to know about Kubernetes networking on Google cloud' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-google-cloud/' %}.

#### IBM Cloud
If you are using IBM Cloud then we recommend using {% include open-new-window.html text='IKS' url='https://www.ibm.com/cloud/container-service/' %}, which has Calico built in to provide cross-subnet IP-in-IP overlay.  In addition to providing network policy for pods, IKS also uses Calico network policies to {% include open-new-window.html text='secure the hosts nodes' url='https://cloud.ibm.com/docs/containers?topic=containers-network_policies#default_policy' %} within the cluster. 

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:IPIP,Routing:BGP' %}

#### Anywhere

The above list of environments is obviously not exhaustive. Understanding the concepts and explanations in this guide has hopefully helped you figure out what is right for your environment. If you still aren't sure then you can ask for advice through the Calico Users's Slack or Discourse forum. And remember you can run Calico in VXLAN overlay mode in almost any environment if you want to get started without worrying too deeply about the different options.

{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:VXLAN,Routing:Calico' %}

### Above and beyond

- {% include open-new-window.html text='Video playlist: Everything you need to know about Kubernetes networking' url='https://www.youtube.com/playlist?list=PLoWxE_5hnZUZMWrEON3wxMBoIZvweGeiq' %}
- [Configure BGP peering]({{ site.baseurl }}/networking/bgp)
- [Configure overlay networking]({{ site.baseurl }}/networking/vxlan-ipip)
- [Advertise Kubernetes service IP addresses]({{ site.baseurl }}/networking/advertise-service-ips)
- [Customize IP address management]({{ site.baseurl }}/networking/ipam)
- [Interoperate with legacy firewalls using IP ranges]({{ site.baseurl }}/networking/legacy-firewalls)