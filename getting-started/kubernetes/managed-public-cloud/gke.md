---
title: Google Kubernetes Engine (GKE)
description: Enable Calico network policy in GKE.
---

### Big picture

Enable Calico in GKE managed Kubernetes service.

### Value

GKE has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. GKE users wanting to go beyond Kubernetes network policy capabilities can make full use of the Calico Network Policy API.

### How to

To enable Calico network policy enforcement, follow these step-by-step instructions:
[Enabling network policy enforcement](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy).

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Host Local,CNI:Calico,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

### Above and beyond

- [Video: Everything you need to know about Kubernetes networking on Google cloud](https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-google-cloud/)
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
