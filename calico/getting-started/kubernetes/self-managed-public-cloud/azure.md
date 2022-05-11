---
title: Self-managed Kubernetes in Microsoft Azure
description: Use Calico with a self-managed Kubernetes cluster in Microsoft Azure.
---

### Big picture

Use {{site.prodname}} with a self-managed Kubernetes cluster in Microsoft Azure. 

### Value

Managing your own Kubernetes cluster (as opposed to using a managed-Kubernetes service like AKS), gives you the most flexibility in configuring {{site.prodname}} and Kubernetes. {{site.prodname}} combines flexible networking capabilities with "run-anywhere" security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability.

### Concepts

**aks-engine** is an open-source tool for creating and managing Kubernetes clusters in Microsoft Azure. It is the core technology for Microsoft’s Azure Kubernetes Service (AKS), but allows you to manage the cluster yourself.

### Before you begin...

- Install {% include open-new-window.html text='kubectl' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}
- Install {% include open-new-window.html text='Azure CLI tools' url='https://docs.microsoft.com/en-us/cli/azure/install-azure-cli' %}

### How to

There are many ways to install and manage Kubernetes in Azure. This guide shows how to use **aks-engine** to deploy a cluster with **Azure’s CNI plugin for networking** and **{{site.prodname}} for network policy enforcement**. The advantage of this approach is that pods are assigned IP addresses associated with Azure Network Interfaces on worker nodes. The IPs come from the VNET network pool and therefore do not require NAT to access resources outside the Kubernetes cluster. However, there are other options that may work better for your environment.

- [aks-engine for Azure networking and Calico network policy](#aks-engine-for-azure-networking-and-calico-network-policy)
- [Other options and tools](#other-options-and-tools)

#### aks-engine for Azure networking and Calico network policy

{% include open-new-window.html text='Install aks-engine' url='https://github.com/Azure/aks-engine/blob/master/docs/tutorials/quickstart.md#install-aks-engine' %} on your workstation.

Before deploying, customize your cluster definition to use {{site.prodname}} for network policy.  Add or modify the `kubernetesConfig` section to include the following (see the {% include open-new-window.html text='aks-engine documentation' url='https://github.com/Azure/aks-engine/blob/master/docs/topics/clusterdefinitions.md#kubernetesconfig' %} for other Kubernetes configuration settings).

```
"kubernetesConfig": {
   "networkPlugin": "azure",
   "networkPolicy": "calico"
 }
```
 
Or, start with this {% include open-new-window.html text='example cluster definition' url='https://github.com/Azure/aks-engine/blob/master/examples/networkpolicy/kubernetes-calico-azure.json' %} with these value already set, and customize to meet your needs. 

Then, {% include open-new-window.html text='follow the ask-engine documentation to deploy your cluster' url='https://github.com/Azure/aks-engine/blob/master/docs/tutorials/quickstart.md#deploy' %}, passing your cluster definition to `aks-engine deploy` via the `-m` flag. 

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Azure,CNI:Azure,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}  

#### Other options and tools

##### {{site.prodname}} networking 

You can also deploy {{site.prodname}} for both networking and policy enforcement. In this mode, {{site.prodname}} uses a VXLAN-based overlay network that masks the IP addresses of the pods from the underlying Azure VNET. This can be useful in large deployments or when running multiple clusters and IP address space is a big concern.

Unfortunately, aks-engine does not support this mode, so you must use a different tool chain to install and manage the cluster. Some options:

- Use [Terraform](#terraform) to provision the Azure networks and VMs, then [kubeadm](#kubeadm) to install the Kubernetes cluster.
- Use [Kubespray](#kubespray)

#### Terraform

Terraform is a tool for automating infrastructure provisioning using declarative configurations.  You can also go as far as automating the install of Docker, kubeadm, and Kubernetes using Terraform “provisioners.” See the {% include open-new-window.html text='Terraform documentation' url='https://www.terraform.io/docs/index.html' %} for more details.

##### kubeadm

{% include open-new-window.html text='kubeadm' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/' %} is a command line tool for bootstrapping a Kubernetes cluster on top of already-provisioned compute resources, like VMs in a cloud or bare metal hosts. Unlike aks-engine which handles provisioning cloud resources, installing Kubernetes, and installing {{site.prodname}}, kubeadm only handles the second step of installing Kubernetes. You should proceed to install {{site.prodname}} after completing kubeadm install. 

##### Kubespray

{% include open-new-window.html text='Kubespray' url='https://kubespray.io/' %} is a tool for provisioning and managing Kubernetes clusters with support for multiple clouds including Azure.  {{site.prodname}} is the default networking provider, or you can set the `kube_network_plugin` variable to `calico`. See the {% include open-new-window.html text='Kubespray docs' url='https://kubespray.io/#/?id=network-plugins' %} for more details.

### Next steps

**Required**
- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Azure' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-azure/' %}
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)
