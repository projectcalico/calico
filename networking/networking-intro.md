---
title: Can you configure Calico networking?
description: Verify that the Calico networking feature is available for you to configure. 
---
It depends. Calico networking is available for configuration if you installed Calico using **Quickstart**, **Self-managed on-premises**, and **Self-managed public cloud**. A good place to start is [Determine best networking option]({{site.baseurl}}/networking/determine-best-networking).

Calico networking **is not available** for you to configure in the following deployments. Content in the Networking section is not relevant to you.

- A managed cloud provider: EKS, GKE, AKS, or IKS
  Although the Calico CNI is used in GKE and IKS, the cloud provider manages the networking; you enforce network policy using Calico network policy and Kubernetes network policy.  
- Flannel
- Istio service mesh