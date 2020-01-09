---
title: Amazon Elastic Kubernetes Service (EKS)
---

### Big picture

Enable Calico in EKS managed Kubernetes service.

### Value

EKS has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. EKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the Calico Network Policy API.

### How to

To enable Calico network policy enforcement, follow these step-by-step instructions:
[Installing Calico on Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/calico.html).

### Above and beyond

- [Everything you need to know about Kubernetes pod networking on AWS](https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/)
- [Install calicoctl command line tool]({{ site.url }}/getting-started/calicoctl/install)
- [Get started with Kubernetes network policy]({{ site.url }}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{ site.url }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.url }}/security/kubernetes-default-deny)
