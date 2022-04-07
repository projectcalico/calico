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

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

1. Create an Azure AKS cluster with no Kubernetes CNI pre-installed. Please refer to [Bring your own CNI with AKS](https://docs.microsoft.com/en-us/azure/aks/use-byo-cni?tabs=azure-cli) for details.

  ```bash
  # Install aks-preview extension
  az extension add --name aks-preview

  # Create a resource group
  az group create --name $RESOURCE_GROUP_NAME --location $LOCATION

  az aks create --resource-group $RESOURCE_GROUP_NAME --name my-calico-cluster --location $LOCATION --network-plugin none

  ```

1. Now that you have a cluster configured, you can install {{site.prodname}}.

{% tabs %}
  <label:Operator,active:true>
<%

1. Install the operator.

   ```bash
   kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
   ```

1. Configure the {{site.prodname}} installation.

   ```bash
   kubectl create -f - <<EOF
   kind: Installation
   apiVersion: operator.tigera.io/v1
   metadata:
     name: default
   spec:
     kubernetesProvider: AKS
     cni:
       type: Calico
     calicoNetwork:
       bgp: Disabled
       ipPools
        - cidr: 10.244.0.0/16
          encapsulation: VXLAN
   EOF
   ```

%>
  <label:Manifest>
<%

1. Install the {{site.prodname}} manifest.

   ```bash
   kubectl apply -f {{ "/manifests/calico-typha.yaml" | absolute_url }}
   ```

2. Configure {{site.prodname}}.

   ```bash
   kubectl -n kube-system set env daemonset/calico-node CALICO_IPV4POOL_VXLAN=Always
   kubectl -n kube-system set env daemonset/calico-node CALICO_IPV4POOL_IPIP=Never
   kubectl -n kube-system set env daemonset/calico-node CALICO_IPV4POOL_CIDR=10.244.0.0/16
   ```
%>
{% endtabs %}

### Next steps

**Required**
- [Install calicoctl command line tool]({{ site.baseurl }}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Azure' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-azure/' %}
- [Get started with Kubernetes network policy]({{ site.baseurl }}/security/kubernetes-network-policy)
- [Get started with {{site.prodname}} network policy]({{ site.baseurl }}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{ site.baseurl }}/security/kubernetes-default-deny)
