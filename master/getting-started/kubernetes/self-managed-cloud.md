---
title: Self-managed public cloud
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/kubernetes/index'
---

### Big picture

Install Kubernetes with Calico and manage your own clusters using a self-managed public cloud offering (AWS and GCE). 

#### Value

If a managed public cloud provider does not provide what you need, several cloud providers offer self-managed versions -- where you maintain all of the servers. 

### How to...

The following public cloud vendors provide Calico networking and/or network policy.

- AWS
  For AWS, review [Determine the best networking option]({{site.baseurl}}/{{page.version}}/determine-best-networking).
  If you require AWS security group and federation, you must install the Calico CNI for networking. 
  - [AWS Install only Calico networking](https://github.com/kubernetes/kops/blob/master/docs/networking.md#calico-example-for-cni-and-network-policy)
  - [AWS, Install only Calico network policy](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy)
- GCE, [Install Calico networking and network policy](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy)

### Above and beyond

- To get started using Calico network policy, see [Get started with Calico policy]({{site.baseurl}}/{{page.version}}/calico-network-policy)
