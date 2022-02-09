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

- Install {% include open-new-window.html text='kubectl' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}
- Install {% include open-new-window.html text='AWS CLI tools' url='https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html' %}

### How to

There are many ways to install and manage Kubernetes in AWS. Using Kubernetes Operations (kops) is a good default choice for most people, as it gives you access to all of {{site.prodname}}’s [flexible and powerful networking features]({{site.baseurl}}/networking). However, there are other options that may work better for your environment.

- [Kubernetes Operations for Calico networking and network policy](#kubernetes-operations-for-calico-networking-and-network-policy)
- [Other options and tools](#other-options-and-tools)

#### Kubernetes Operations for Calico networking and network policy

To use kops to create a cluster with {{site.prodname}} networking and network policy:

1. {% include open-new-window.html text='Install kops' url='https://kops.sigs.k8s.io/install/' %} on your workstation.
1. {% include open-new-window.html text='Set up your environment for AWS' url='https://kops.sigs.k8s.io/getting_started/aws/' %} .
  1. Be sure to {% include open-new-window.html text='set up an S3 state store' url='https://kops.sigs.k8s.io/getting_started/aws/#cluster-state-storage' %} and export its name:
  
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

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:etcd' %}   

You can further customize the {{site.prodname}} install with {% include open-new-window.html text='options listed in the kops documentation' url='https://kops.sigs.k8s.io/networking/#calico-example-for-cni-and-network-policy' %}. 

#### Other options and tools

##### Amazon VPC CNI plugin

As an alternative to {{site.prodname}} for both networking and network policy, you can use Amazon’s VPC CNI plugin for networking, and {{site.prodname}} for network policy. The advantage of this approach is that pods are assigned IP addresses associated with Elastic Network Interfaces on worker nodes. The IPs come from the VPC network pool and therefore do not require NAT to access resources outside the Kubernetes cluster.

Set your kops cluster configuration to:

```
networking:
  amazonvpc: {}
```
Then install {{site.prodname}} for network policy only after the cluster is up and ready.

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:AWS,CNI:AWS,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

##### Kubespray

{% include open-new-window.html text='Kubespray' url='https://kubespray.io/' %} is a tool for provisioning and managing Kubernetes clusters with support for multiple clouds including Amazon Web Services. {{site.prodname}} is the default networking provider, or you can set the `kube_network_plugin` variable to `calico`. See the {% include open-new-window.html text='Kubespray docs' url='https://kubespray.io/#/?id=network-plugins' %} for more details.

### Next steps

**Required**
- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes pod networking on AWS' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/' %}
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)
