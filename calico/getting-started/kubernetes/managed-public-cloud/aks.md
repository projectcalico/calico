---
title: Microsoft Azure Kubernetes Service (AKS)
description: Enable Calico network policy in AKS.
---

### Big picture

Enable {{site.prodname}} in AKS managed Kubernetes service.

### Value

AKS has built-in support for {{site.prodname}}, providing a robust implementation of the full Kubernetes Network Policy API. AKS users wanting to go beyond Kubernetes network policy capabilities can make full use of the {{site.prodname}} Network Policy API.

You can also use {{site.prodname}} for networking on AKS in place of the default Azure VPC networking. This allows you to take advantage of the full set of {{site.prodname}} networking features.

### How to

#### Install AKS with {{site.prodname}} for network policy

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Azure,CNI:Azure,Overlay:No,Routing:VPC Native,Datastore:Kubernetes' %}

To enable {{site.prodname}} network policy enforcement, follow these step-by-step instructions: {% include open-new-window.html text='Create an AKS cluster and enable network policy' url='https://docs.microsoft.com/en-us/azure/aks/use-network-policies' %}.

#### Install AKS with {{site.prodname}} networking

**Limitations**
- [Windows dataplane]({{ site.baseurl }}/getting-started/windows-calico) is not supported.
- [eBPF dataplane]({{ site.baseurl }}/maintenance/ebpf/use-cases-ebpf) is not supported.
- [VPP dataplane](https://github.com/projectcalico/vpp-dataplane) is not supported.


The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

1. Create an Azure AKS cluster with no Kubernetes CNI pre-installed. Please refer to [Bring your own CNI with AKS](https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli) for details.
   ``` 
    # Install aks-preview extension
    az extension add --name aks-preview
    # Update aks-preview to ensure latest version is installed
    az extension update --name aks-preview

    # Create a resource group
    az group create --name my-calico-rg --location westcentralus

    az aks create --resource-group my-calico-rg --name my-calico-cluster --location westcentralus --network-plugin none
    ```

1. Get credentials to allow you to access the cluster with `kubectl`:
    ```
    az aks get-credentials --resource-group my-calico-rg --name my-calico-cluster
    ```

1. Now that you have a cluster configured, you can install {{site.prodname}}.

1. Install the operator.

   ```
   kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
   ```

1. Configure the {{site.prodname}} installation.

   ```
   kubectl create -f {{ "/manifests/aks-byo-installation.yaml" | absolute_url }}
   ```

1. Confirm that all of the pods are running with the following command.

   ```
   watch kubectl get pods -n calico-system
   ```

   Wait until each pod has the `STATUS` of `Running`.
 

### Next steps

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Azure' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-azure/' %}
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with {{site.prodname}} network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
