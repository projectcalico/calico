---
title: Microsoft Azure Kubernetes Service (AKS)
description: Enable Calico network policy in AKS.
---

### Big picture

Enable {{site.prodname}} in AKS managed Kubernetes service.

### Value

AKS has built-in support for {{site.prodname}}, providing a robust implementation of the full Kubernetes Network Policy API. AKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the {{site.prodname}} Network Policy API. 

### How to

To enable {{site.prodname}} network policy enforcement, follow these step-by-step instructions: {% include open-new-window.html text='Create an AKS cluster and enable network policy' url='https://docs.microsoft.com/en-us/azure/aks/use-network-policies' %}.

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Azure,CNI:Azure,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

### Next steps

**Required**
- [Install calicoctl command line tool]({{ site.baseurl }}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Azure' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-azure/' %}
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with {{site.prodname}} network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
