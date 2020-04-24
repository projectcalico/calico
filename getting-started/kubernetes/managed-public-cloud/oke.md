---
title: Oracle Cloud Container Engine for Kubernetes (OKE)
description: Installing Calico and Setting Up Network Policies.
---

### Big picture

Enable Calico in OKE managed Kubernetes service.

### Value

Clusters you create with Oracle Container Engine for Kubernetes (OKE) have flannel installed as the default CNI network provider. Flannel is a simple overlay virtual network that satisfies the requirements of the Kubernetes networking model by attaching IP addresses to containers. 

Although flannel satisfies the requirements of the Kubernetes networking model, it does not support NetworkPolicy resources. If you want to enhance the security of clusters you create with Oracle Container Engine for Kubernetes by implementing network policies, you have to install and configure a network provider that does support NetworkPolicy resources. One such provider is Calico (refer to the [Kubernetes documentation](https://kubernetes.io/docs/concepts/cluster-administration/networking/#how-to-implement-the-kubernetes-networking-model) for a list of other network providers). Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads. For more information about Calico, see the [Calico documentation](https://docs.projectcalico.org/latest/introduction/).

You can manually install Calico alongside flannel in clusters you have created using Oracle Container Engine for Kubernetes.

### How to

Having created a cluster using Oracle Container Engine for Kubernetes (using either the Console or the API), you can subsequently install Calico on the cluster (alongside flannel) to support network policies.

For convenience, Calico installation instructions are included below. Note that Calico installation instructions vary between Calico versions. For information about installing different versions of Calico, always refer to the [Calico documentation for installing Calico for network policy enforcement only](https://docs.projectcalico.org/latest/getting-started/kubernetes/installation/other).

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:IPIP,Routing:BGP,Datastore:Kubernetes' %}

### Above and beyond

- [Installing Calico manually on OKE](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengsettingupcalico.htm)
- [Overview of Container Engine for Kubernetes](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm)
- [Install calicoctl command line tool]({{ site.baseurl }}/getting-started/clis/calicoctl/install)
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{ site.baseurl }}/security/calico-network-policy)
