---
title: IBM Cloud Kubernetes Service (IKS)
description: Use IKS with built-in support for Calico networking and network policy.
---

### Big picture

Enable {{site.prodname}} in IKS managed Kubernetes service.

### Value

IKS has built-in support for {{site.prodname}}, providing a robust implementation of the full Kubernetes Network Policy API. IKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the {{site.prodname}} Network Policy API. In addition to using {{site.prodname}} to secure Kubernetes pods, IKS also uses {{site.prodname}} host endpoint capabilities to provide additional security for the nodes in your cluster.

### How to

{{site.prodname}} networking and network policy are automatically installed and configured in your {% include open-new-window.html text='IBM Cloud Kubernetes Service' url='https://www.ibm.com/cloud/container-service/' %}. Default policies are created to protect your Kubernetes cluster, with the option to create your own policies to protect specific services.

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Cross-subnet:IPIP,Routing:BGP,Datastore:Kubernetes' %}

### Next steps

**Required**
- [Install calicoctl command line tool]({{ site.baseurl }}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Controlling traffic with network policies for IKS' url='https://cloud.ibm.com/docs/containers?topic=containers-network_policies' %}
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{ site.baseurl }}/security/calico-network-policy)
