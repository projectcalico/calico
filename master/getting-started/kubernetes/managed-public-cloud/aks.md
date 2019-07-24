---
title: Microsoft Azure Kubernetes Service (AKS)
---

### Big picture

Enable Calico in AKS managed Kubernetes service.

### Value

AKS has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. AKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the Calico Network Policy API. 

### How to

To enable Calico network policy enforcement, follow these step-by-step instructions: 
[Create an AKS cluster and enable network policy](https://docs.microsoft.com/en-us/azure/aks/use-network-policies).

### Above and beyond

- [Install calicoctl command line tool]({{site.url}}/{{page.version}}/getting-started/calicoctl/install)
- [Get started with Kubernetes network policy]({{site.url}}/{{page.version}}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{site.url}}/{{page.version}}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{site.url}}/{{page.version}}/security/kubernetes-default-deny)
