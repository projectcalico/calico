---
title: Determine network plugin and datastore
description: Determine your network CNI
canonical_url: 
---

### Big picture

Understand networking plugin and datastore options before installing {{ site.prodNameWindows }}. Because of the varied networking options available, your deployment platform, and Windows limitations, it is important to decide your networking first. 

### Concepts

The {{ site.prodNameWindows }} deployment requires a hybrid Linux/Windows Kubernetes cluster; the Linux cluster contains the {{site.prodname}} cluster-wide components, and Windows nodes are joined to that cluster. Kubernetes currently requires a Linux master node (which may also be used as the required Linux worker node).

Linux and Windows dataplanes have different requirements:

- **Linux**
    
  {{site.prodname}} always requires the {{site.prodname}} CNI plugin, and is auto-installed on Windows. 

- **Windows** 
    
   The required CNI plugin differs by network provider.

### How to

- [Determine your network plugin](#determine-your-network-plugin)
- [Review Window limitations with BGP](#review-window-limitations-with-bgp)
- [Determine datastore](#determine-datastore)

#### Determine your network plugin

The following table summarizes the networking options and considerations.

| Networking                                                   | Components                                                   | **Value/Content**                                            |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| {{site.prodname}} BGP<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /> | Windows CNI plugin:<br/>calico.exe<br /><br />Linux: {{site.prodname}} for policy and networking<br /><br /><br /><br /><br /><br /> | {{site.prodname}}'s native networking approach, supports:<br/>- Auto-configured node-to-node BGP mesh over an L2 fabric<br/>- Peering with external routers for an L3 fabric<br/>- {{site.prodname}} IPAM and IP aggregation (with some limitations)<br/>- Route reflectors (including the new in-cluster route reflector introduced in {{site.prodname}} v3.3). **Note**: Windows node cannot act as route reflectors.<br/>- Both etcd and Kubernetes API datastore drivers<br/><br />**AWS users**: If running on AWS, you must disable the source/dest check on your EC2 instances so that hosts can forward traffic on behalf of pods. |
| {{site.prodname}} VXLAN<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /> | Windows CNI plugin:<br/>calico.exe<br /><br />Linux: {{site.prodname}} for policy and networking<br /><br /><br /><br /><br /><br /> | {{site.prodname}}'s VXLAN overlay, supports:<br/>- VXLAN overlay, which can traverse most networks.<br/>- Auto-configured node-to-node routing<br/>- {{site.prodname}} IPAM and IP aggregation (with some limitations)<br/>- Both etcd and Kubernetes API datastore drivers<br/><br />**Requires**:<br/>- Windows 1903 insider preview 18317 or greater<br/>- Windows Server 2019 / 1809 (RS5), with network policy limitations.<br /><br />**Note**: VXLAN runs on UDP port 4789 (this is the only port supported by Windows), remember to open that port between your {{site.prodname}} hosts in any firewalls / security groups. |
| Static routes<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /> | Windows CNI plugin: win-bridge.exe<br /><br />Linux: {{site.prodname}} policy-only<br /><br /><br /> | Simplest but most manual solution.<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /> |
| Cloud provider<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /> | Windows CNI plugin: win-bridge.exe<br /><br />Linux: {{site.prodname}} policy-only<br /><br /><br /><br /><br /> | A useful fallback, particularly if you have a Kubernetes cloud provider that automatically installs inter-host routes. {{site.prodname}} has been tested with the standard **win-bridge.exe** CNI plugin so it should work with any networking provider that ultimately uses win-bridge.exe to network the pod (such as the Azure CNI plugin and cloud provider).<br /><br /><br /><br /><br /><br /><br /> |

### Review Windows limitations with BGP

If you are using {{site.prodname}} with BGP, note these current limitations with Windows.

| Feature                                                      | Limitation                                                   |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| IP mobility/ borrowing <br /><br /><br /><br /><br /><br /><br /> | {{site.prodname}} IPAM allocates IPs to host in blocks for aggregation purposes.<br/>If the IP pool is full, nodes can also "borrow" IPs from another node's block. In BGP terms, the borrower then advertises a more specific "/32" route for the borrowed IP and traffic for that IP only is routed to the borrowing host. (This also allows for IP mobility in the {{site.prodname}} OpenStack integration.)<br/><br />Windows nodes do not support this borrowing mechanism; they will not borrow IPs even if the IP pool is full and they mark their blocks so that Linux nodes will not borrow from them. |
| IPs reserved for<br/>Windows<br /><br /><br /><br /><br />   | {{site.prodname}} IPAM allocates IPs in CIDR blocks. Due to networking requirements on Windows, four IPs per Windows node-owned block must be reserved for internal purposes.<br /><br/>For example, with the default block size of /26, each block contains 64 IP addresses, 4 are reserved for Windows, leaving 60 for pod networking.<br /><br />To reduce the impact of these reservations, a larger block size can be configured at the IP pool scope (before any pods are created). |
| Single IP block per host<br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /> | {{site.prodname}} IPAM is designed to allocate blocks of IPs (default size /26) to hosts on demand. While the {{site.prodname}} CNI plugin was written to do the same, kube-proxy currently only supports a single IP block per host. Tigera is working with Microsoft to find a resolution.<br/><br />To work around the default limit of one /26 per host there some options:<br/><br />- With {{site.prodname}} BGP networking and the etcd datastore before creating any blocks, change the block size used by the IP pool so that it is sufficient for the largest number of Pods that are to be used on a single Windows host.<br/>- Use {{site.prodname}} BGP networking with the kubernetes datastore. In that mode, {{site.prodname}} IPAM is not used and the CNI host-local IPAM plugin is used with the node's Pod CIDR.<br/><br />To allow multiple IPAM blocks per host (at the expense of kube-proxy compatibility), set the `windows_use_single_network` flag to `false` in the `cni.conf.template` before installing {{site.prodname}}. Changing that setting after pods are networked is not recommended because it may leak HNS endpoints. |
| IP-in-IP overlay                                             | {{site.prodname}}'s IPIP overlay mode cannot be used in clusters that contain Windows nodes because Windows does not support IP-in-IP. |
| NAT-outgoing<br /><br /><br /><br /><br /><br /><br /><br /> | {{site.prodname}} IP pools support a "NAT outgoing" setting with the following behaviour: <br />- Traffic between {{site.prodname}} workloads (in any IP pools) is not NATted. <br />- Traffic leaving the configured IP pools is NATted if the workload has an IP within an IP pool that has NAT outgoing enabled. {{ site.prodNameWindows }} honors the above setting but it is only applied at pod creation time. If the IP pool configuration is updated after a pod is created, the pod's traffic will continue to be NATted (or not) as before. NAT policy for newly-networked pods will honor the new configuration. {{ site.prodNameWindows }} automatically adds the host itself and its subnet to the NAT exclusion list. This behaviour can be disabled by setting flag `windows_disable_host_subnet_nat_exclusion` to `true` in `cni.conf.template` before running the install script. |
| Service IP advertisement                                     | This {{site.prodname}} feature is not supported on Windows.  |

### Determine datastore

| **Networking mode**     | **etcd datastore** support? | Kubernetes API datastore support? |
| ----------------------- | --------------------------- | --------------------------------- |
| {{site.prodname}} BGP              | Yes                         | Yes                               |
| {{site.prodname}} VXLAN            | Yes                         | Yes                               |
| static routes/other CNI | No                          | Yes                               |

Because {{site.prodname}} requires the same datastore to be used across the entire Kubernetes cluster, the same support applies to Linux nodes. 

### Next steps

You are now ready to:

- Review [requirements]({{site.baseurl}}/getting-started/windows-calico/requirements) 
- [Install {{site.prodNameWindows}}]({{site.baseurl}}/getting-started/windows-calico/install)
