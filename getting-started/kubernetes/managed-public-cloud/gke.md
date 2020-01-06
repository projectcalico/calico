---
title: Google Kubernetes Engine (GKE)
---

### Big picture

Enable Calico in GKE managed Kubernetes service.

### Value

GKE has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. GKE users wanting to go beyond Kubernetes network policy capabilities can make full use of the Calico Network Policy API.

### How to

To enable Calico network policy enforcement, follow these step-by-step instructions:
[Enabling network policy enforcement](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy).

### Above and beyond

- [Get started with Kubernetes network policy]({{ site.url }}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{ site.url }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.url }}/security/kubernetes-default-deny)
