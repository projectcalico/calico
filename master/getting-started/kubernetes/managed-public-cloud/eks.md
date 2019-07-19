---
title: Amazon Elastic Kubernetes Service (EKS)
---

### Big picture

Enable Calico in EKS managed Kubernetes service.

### Value

EKS has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. EKS users wanting to go beyond Kubernetes network policy capabilities, can make full use of the Calico Network Policy API.

### How to

To enable Calico network policy enforcement, follow these step-by-step instructions:
[Installing Calico on Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/calico.html).

### Above and beyond

- [Install calicoctl command line tool]({{site.url}}/{{page.version}}/getting-started/calicoctl/install)
- [Get started with Kubernetes network policy]({{site.url}}/{{page.version}}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{site.url}}/{{page.version}}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{site.url}}/{{page.version}}/security/kubernetes-default-deny)