---
title: Deploying Calico on Azure
canonical_url: https://docs.projectcalico.org/v3.0/reference/public-cloud/azure
---

## About {{site.prodname}} on Azure

While Azure does not support {{site.prodname}} networking, you can use
{{site.prodname}} policy with one of the following networking options.

- **Azure user-defined routes**: This option provides networking without overlays.
  Disable {{site.prodname}} networking by setting `CALICO_NETWORKING_BACKEND` to `none` 
  in `{{site.nodecontainer}}`. (Also called "policy-only mode".) Refer to 
  [Configuring calico/node](../node/configuration) and [Azure user-defined routes](#azure-user-defined-routes) for more information. If you're on Kubernetes, refer to the [Kubernetes API datastore](../../getting-started/kubernetes/installation/hosted/kubernetes-datastore/#policy-only) installation guide for a sample manifest.

- **flannel** (Kubernetes only): Refer to the [flannel installation guide](../../getting-started/kubernetes/installation/hosted/canal) 
  for specific instructions and a manifest. This option does use overlays.

- **Azure CNI IPAM plug-in**: Configure {{site.prodname}} to use the 
  [Azure CNI plug-in](https://github.com/Azure/azure-container-networking/blob/master/docs/cni.md)
  instead of the {{site.prodname}} CNI plug-in.


## Azure user-defined routes

To configure Azure user-defined routes (UDR):

- Create an [Azure route table][AzureUDRCreate]{:target="_blank"} and 
  associatе it with the VMs subnet.

- Enable [IP forwarding enabled][AzureIPForward]{:target="_blank"} in your 
  VM network interfaces.

On Kubernetes, also complete the following.

- Ensure that the selected pod's subnet is a part of your Azure virtual 
  network IP range.
  
- Include the name of your routing table in the configuration file of your 
  Kubernetes Azure cloud provider.

## Why doesn't Azure support {{site.prodname}} networking?

Azure does not allow traffic with unknown source IPs.

[AzureIPForward]: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-network-interface#enable-or-disable-ip-forwarding
[AzureUDR]: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview#user-defined
[AzureUDRCreate]: https://docs.microsoft.com/en-us/azure/virtual-network/create-user-defined-route-portal
[PolicyMode]: {{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/#policy-only