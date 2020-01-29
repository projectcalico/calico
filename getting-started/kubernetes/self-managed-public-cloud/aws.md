---
title: Self-managed Kubernetes in Amazon Web Services (AWS)
description: Use Calico with a self-managed Kubernetes cluster in Amazon Web Services (AWS).
---

### Big picture

Use {{site.prodname}} with a self-managed Kubernetes cluster in Amazon Web Services (AWS). 

### Value

Managing your own Kubernetes cluster (as opposed to using a managed-Kubernetes service like EKS), gives you the most flexibility in configuring {{site.prodname}} and Kubernetes. {{site.prodname}} combines flexible networking capabilities with "run-anywhere" security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability.

### Concepts

Kubernetes Operations (kops) is a cluster management tool that handles provisioning cluster VMs and installing Kubernetes. It has built-in support for using {{site.prodname}} as the Kubernetes networking provider.

### Before you begin...

- Install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- Install [AWS CLI tools](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)

### How to

There are many ways to install and manage Kubernetes in AWS. Using Kubernetes Operations (kops) is a good default choice for most people, as it gives you access to all of {{site.prodname}}’s [flexible and powerful networking features]({{site.baseurl}}/networking). However, there are other options that may work better for your environment.

- [Kubernetes Operations for Calico networking and network policy](#kubernetes-operations-for-calico-networking-and-network-policy)
- [Other options and tools](#other-options-and-tools)

#### Kubernetes Operations for Calico networking and network policy

To use kops to create a cluster with {{site.prodname}} networking and network policy:

1. [Install kops](https://kops.sigs.k8s.io/install/) on your workstation.
1. [Set up your environment for AWS](https://kops.sigs.k8s.io/getting_started/aws/).
  1. Be sure to [set up an S3 state store](https://kops.sigs.k8s.io/getting_started/aws/#cluster-state-storage) and export its name:
  
     ```
     export KOPS_STATE_STORE=s3://name-of-your-state-store-bucket
     ```
1. Configure kops to use {{site.prodname}} for networking.  
   The easiest way to do this is to pass `--networking calico` to kops when creating the cluster. For example:

   ```
   kops create cluster \
    --zones us-west-2a \
    --networking calico \
    name-of-your-cluster
   ```
   Or, you you can add `calico` to your cluster config.  Run kops edit cluster and set the following networking configuration.

   ```
   networking:
     calico: {}
   ```
   You can further customize the {{site.prodname}} install with [options listed in the kops documentation](https://kops.sigs.k8s.io/networking/#calico-example-for-cni-and-network-policy). 

#### Other options and tools

##### Amazon VPI CNI plugin

As an alternative to {{site.prodname}} for both networking and network policy, you can use Amazon’s VPC CNI plugin for networking, and {{site.prodname}} for network policy. The advantage of this approach is that pods are assigned IP addresses associated with Elastic Network Interfaces on worker nodes. The IPs come from the VPC network pool and therefore do not require NAT to access resources outside the Kubernetes cluster.

Set your kops cluster configuration to:

```
networking:
  amazonvpc: {}
```
Then install {{site.prodname}} for network policy only after the cluster is up and ready.

##### Kubespray

[Kubespray](https://kubespray.io/) is a tool for provisioning and managing Kubernetes clusters with support for multiple clouds including Amazon Web Services. {{site.prodname}} is the default networking provider, or you can set the `kube_network_plugin` variable to `calico`. See the [Kubespray docs](https://kubespray.io/#/?id=network-plugins) for more details.

### Above and beyond

- [Install and configure calicoctl]({{site.baseurl}}/getting-started/calicoctl/install)
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)
