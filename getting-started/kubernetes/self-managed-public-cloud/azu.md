---
title: Self-managed Kubernetes in Microsoft Azure
description: Use Calico with a self-managed Kubernetes cluster in Microsoft Azure.
---

### Big picture

Use {{site.prodname}} with a self-managed Kubernetes cluster in Microsoft Azure. 

### Value

Managing your own Kubernetes cluster (as opposed to using a managed-Kubernetes service like AKS), gives you the most flexibility in configuring {{site.prodname}} and Kubernetes. {{site.prodname}} provides both **networking** and **network security** for containers, virtual machines, and native host-based workloads across a broad range of platforms including Kubernetes, OpenShift, Docker EE, OpenStack, and bare metal services. {{site.prodname}} combines flexible networking capabilities with "run-anywhere" security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability.

### Concepts

**aks-engine** is an open-source tool for creating and managing Kubernetes clusters in Microsoft Azure. It is the core technology for Microsoft’s Azure Kubernetes Service (AKS), but allows you to manage the cluster yourself.

### Before you begin...

- Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- Install [Azure CLI tools](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)

### How to

There are many ways to install and manage Kubernetes in Azure. This guide shows how to deploy a cluster with **Azure’s CNI plugin for networking** and **{{site.prodname}} for network policy enforcement**, using **aks-engine**. The advantage of this approach is that pods are assigned IP addresses associated with Azure Network Interfaces on worker nodes. The IPs come from the VNET network pool and therefore do not require NAT to access resources outside the Kubernetes cluster. However, there are other options that may work better for your environment.

- [aks-engine for Azure networking and calico network policy](#aks-engine-for-azure-networking-and-calico-network-policy)
- [Other options and tools](#other-options-and-tools)

#### aks-engine for Azure networking and Calico network policy

[Install aks-engine](https://github.com/Azure/aks-engine/blob/master/docs/tutorials/quickstart.md#install-aks-engine) on your workstation.

Before deploying, customize your cluster definition to use {{site.prodname}} for network policy.  Add or modify the `kubernetesConfig` section to include the following (see the [aks-engine documentation](https://github.com/Azure/aks-engine/blob/master/docs/topics/clusterdefinitions.md#kubernetesconfig) for other Kubernetes configuration settings).

```
"kubernetesConfig": {
   "networkPlugin": "azure",
   "networkPolicy": "calico"
 }
```
 
Or, start with this [example cluster definition](https://github.com/Azure/aks-engine/blob/master/examples/networkpolicy/kubernetes-calico-azure.json) with these value already set, and customize to meet your needs. 

Then, [follow the ask-engine documentation to deploy your cluster](https://github.com/Azure/aks-engine/blob/master/docs/tutorials/deploy.md), passing your cluster definition to `ask-engine deploy` via the `-m` flag. 

#### Other options and tools

##### {{site.prodname}} networking 

You can also deploy {{site.prodname}} for both networking and policy enforcement. In this mode, {{site.prodname}} uses a VXLAN-based overlay network that masks the IP addresses of the pods from the underlying Azure VNET. This can be useful in large deployments or when running multiple clusters and IP address space is a big concern.

Unfortunately, aks-engine does not support this mode, so you will have to use a different tool chain to install and manage the cluster. One option is to use Terraform to provision the Azure networks and VMs, then kubeadm to install the Kubernetes cluster.

### Above and beyond

- [Install and configure calicoctl]({{site.baseurl}}/getting-started/calicoctl/install)
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)