---
title: Amazon Elastic Kubernetes Service (EKS)
description: Enable Calico network policy in EKS.
---

### Big picture

Enable Calico in EKS managed Kubernetes service.

### Value

EKS has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. EKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the Calico Network Policy API.

### How to

To enable Calico network policy enforcement, follow these step-by-step instructions: {% include open-new-window.html text='Installing Calico on Amazon EKS' url='https://docs.aws.amazon.com/eks/latest/userguide/calico.html' %}

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:AWS,CNI:AWS,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

### Next steps

**Required**
- [Install calicoctl command line tool]({{ site.baseurl }}/getting-started/clis/calicoctl/install)

**Recommended**
- [Video: Everything you need to know about Kubernetes pod networking on AWS](https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/)
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
