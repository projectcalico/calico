---
title: Get started with IP address management
description: Configure Calico to use Calico IPAM or host-local IPAM, and when to use one or the other.
---

### Big picture

Understand how IP address management (IPAM) functions in a Kubernetes cluster using Calico.

### Value

Different IPAM techniques provide different feature sets. Calico’s IPAM provides additional IP allocation efficiency and flexibility compared to other address management approaches. 

### Features

This how-to guide uses the following Calico features:

- **Calico IPAM**
- **Integration with host-local IPAM**
- **IPPool resource**

### Concepts

#### IPAM in Kubernetes 

Kubernetes uses IPAM plugins to allocate and manage IP addresses assigned to pods. Different IPAM plugins provide different feature sets. Calico provides its own IPAM plugin called **calico-ipam** which is designed to work well with Calico and includes a number of features. 

#### Calico IPAM

The **calico-ipam** plugin uses Calico’s IP pool resource to control how IP addresses are allocated to pods within the cluster. This is the default plugin used by most Calico installations.

By default, Calico uses a single IP pool for the entire Kubernetes pod CIDR, but you can divide the pod CIDR into several pools. You can assign separate IP pools to particular selections of **nodes**, or to teams, users, or applications within a cluster using **namespaces**. 

You can control which pools Calico uses for each pod using

- node selectors
- an annotation on the pod’s namespace, or
- an annotation on the pod

Calico also supports the **host-local** IPAM plugin. However, when using the host-local IPAM plugin some Calico features are not available.

#### Calico IPAM blocks

In Calico IPAM, IP pools are subdivided into blocks -- smaller chunks that are associated with a particular node in the cluster. Each node in the cluster can have one or more blocks associated with it. Calico will automatically create and destroy blocks as needed as the number of nodes and pods in the cluster grows or shrinks.

Blocks allow Calico to efficiently aggregate addresses assigned to pods on the same node, reducing the size of the routing table. By default Calico will try to allocate IP addresses from within an associated block, creating a new block if necessary. Calico can also assign addresses to pods on a node that are not within a block associated with that node. This allows for IP allocations independent of the node on which a pod is launched.

By default, Calico creates blocks with room for 64 addresses (a /26), but you can control block sizes for each IP pool.

#### Host-local IPAM

The host-local plugin is a simple IP address management plugin. It uses predetermined CIDRs statically allocated to each node in order to choose addresses for pods. Once set, the CIDR for a node cannot be modified. Pods can be assigned addresses only from within the CIDR allocated to the node.

Calico can use the host-local IPAM plugin, using the **Node.Spec.PodCIDR** field in the Kubernetes API to determine the CIDR to use for each node. However, per-node, per-pod, and per-namespace IP allocation features are not available using the host-local plugin.

The host-local IPAM plugin is primarily used by other methods of routing pod traffic from one host to another. For example, it is used when installing Calico for policy enforcement with flannel networking, as well as when using Calico in Google Kubernetes Engine (GKE).

### How to

#### Install Calico with calico-ipam

Follow one of the [getting started guides]({{ site.baseurl }}/getting-started/) to install Calico.

#### Install Calico with host-local IPAM

Follow one of the [getting started guides]({{ site.baseurl }}/getting-started/) to install Calico with flannel networking, or on GKE.

Or, see the [reference documentation on host-local IPAM]({{ site.baseurl }}/reference/cni-plugin/configuration#using-host-local-ipam).

### Tutorial

For a blog/tutorial on IP pools, see {% include open-new-window.html text='Calico IPAM: Explained and Enhanced' url='https://www.tigera.io/blog/calico-ipam-explained-and-enhanced/' %}.

### Above and beyond

- [IP Pool]({{ site.baseurl }}/reference/resources/ippool)

There are several other ways to leverage Calico IPAM including:

- [Assign addresses based on topology]({{ site.baseurl }}/networking/assign-ip-addresses-topology)
- [Use a specific address for a pod]({{ site.baseurl }}/networking/use-specific-ip)
- [Migrate from one IP pool to another]({{ site.baseurl }}/networking/migrate-pools)
- [Interoperate with legacy firewalls using IP ranges]({{ site.baseurl }}/networking/legacy-firewalls)
- [View IP address utilization]({{ site.baseurl }}/reference/calicoctl/ipam/show)
- [Change IP address block size]({{ site.baseurl }}/reference/resources/ippool)
