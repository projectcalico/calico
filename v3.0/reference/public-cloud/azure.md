---
title: Deploying Calico on Azure
canonical_url: https://docs.projectcalico.org/v3.3/reference/public-cloud/azure
---

{{site.prodname}} in [Microsoft Azure][Azure]{:target="_blank"} is supported in [policy-only][PolicyMode] mode. {{site.prodname}} IPAM needs to be configured in host-local mode and used in conjunction with Kubernetes pod CIDR assignments. Additional option would be to use [Canal][Canal] - {{site.prodname}} with flannel networking.

#### Routing Traffic

##### Azure user-defined routes (Azure UDR)

[Azure user-defined routes][AzureUDR] is the only available option for traffic routing without overlay networking. To use Azure routing you must create [Azure route table][AzureUDRCreate]{:target="_blank"} and associatе it with VMs subnet.

##### Flannel networking

Refer to the following [Kubernetes self-hosted install guide][CanalGuide] in the Canal project for details on installing Calico with flannel.

#### Enabling IP forwarding (only for Azure UDR)

To allow pod traffic make sure VM network interfaces have [IP forwarding enabled][AzureIPForward]{:target="_blank"} in Azure.

#### Enabling Kubernetes pod CIDR assignment (only for Azure UDR)

To enable automatic pod CIDR assignment make sure Kubernetes controller manager has `allocate-node-cidrs` set to `true`
and a proper subnet in the `cluster-cidr` parameter. Make sure that the selected pod's subnet is a part of your Azure virtual network IP range.
You also must have Kubernetes Azure cloud provider configured with your routing table name in configuration file.

#### Why doesn't Azure support {{site.prodname}} networking?

Azure does not allow BGP, IPIP traffic, and traffic with unknown source IPs.

[Azure]: https://azure.microsoft.com
[AzureIPForward]: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-network-interface#enable-or-disable-ip-forwarding
[AzureUDR]: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview#user-defined
[AzureUDRCreate]: https://docs.microsoft.com/en-us/azure/virtual-network/create-user-defined-route-portal
[Canal]: https://github.com/projectcalico/canal
[CanalGuide]: https://github.com/projectcalico/canal/blob/master/k8s-install/README.md
[PolicyMode]: {{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/#policy-only
