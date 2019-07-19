---
title: IBM Cloud Kubernetes Service (IKS)
---

### Big picture

Enable Calico in IKS managed Kubernetes service.

### Value

IKS has built-in support for Calico, providing a robust implementation of the full Kubernetes Network Policy API. IKS users wanting to go beyond Kubernetes network policy capabilities, can make full use of the Calico Network Policy API. In addition to using Calico to secure Kubernetes pods, IKS also uses Calico host endpoint capabilities to provide additional security for the nodes in your cluster.

### How to

Calico networking and network policy are automatically installed and configured in your [IBM Cloud Kubernetes Service](https://www.ibm.com/cloud/container-service/). Default policies are created to protect your Kubernetes cluster, with the option to create your own policies to protect specific services.

### Above and beyond

- [Controlling traffic with network policies for IKS](https://cloud.ibm.com/docs/containers?topic=containers-network_policies)
- [Install calicoctl command line tool]({{site.url}}/{{page.version}}/getting-started/calicoctl/install)
- [Get started with Kubernetes network policy]({{site.url}}/{{page.version}}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{site.url}}/{{page.version}}/security/calico-network-policy)