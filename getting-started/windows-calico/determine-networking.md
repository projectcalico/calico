---
title: Determine network plugin and datastore
description: Determine your network CNI
canonical_url: TBD
---

### Big picture

Understand networking plugin and datastore options before installing Calico for Windows. Because of the varied networking options available, your deployment platform, and Windows limitations, it is important to decide your networking first. 

### Concepts

The Calico for Windows deployment requires a hybrid Linux/Windows Kubernetes cluster; the Linux cluster contains the Calico cluster-wide components, and Windows nodes are joined to that cluster. Kubernetes currently requires a Linux master node (which may also be used as the required Linux worker node).

Linux and Windows dataplanes have different requirements:

- **Linux**
    Calico always requires the Calico CNI plugin (even if inter-node networking is being provided by flannel), and is auto-installed on Windows. 

- **Windows** 
    The CNI plugin that is required, differs by network provider.

### How to

- [Determine your network plugin](#determine-your-network-plugin)
- [Review Window limitations with BGP](#review-window-limitations-with-bgp)
- [Determine datastore](#determine-datastore)

#### Determine your network plugin

The following table summarizes the networking options and considerations.

| **Option**                                                   | **Requires**                                                 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Calico BGP networking<br />- Windows CNI plugin: calico.exe<br />- Linux: Calico for policy and networking | Calico's native networking approach, supports:<br/>-  Auto-configured node-to-node BGP mesh over an L2 fabric
- Peering with external routers for an L3 fabric
- Calico IPAM and IP aggregation [with some limitations]()
- Route reflectors (including the new in-cluster route reflector introduced in Calico v3.3) **Note**: Windows nodes cannot act as route reflectors.
- Both etcd and Kubernetes API datastore drivers
<br />**Note for AWS users**: If running on AWS, you must disable the source/dest check on your EC2 instances so that hosts can forward traffic on behalf of pods. |
| Calico VXLAN networking <br />- Windows CNI plugin: calico.exe<br />- Linux: Calico for policy and networking | Calico's VXLAN overlay, supports:<br/>- VXLAN overlay, which can traverse most networks.
- Auto-configured node-to-node routing
- Calico IPAM and IP aggregation [with some limitations]
- Both etcd and Kubernetes API datastore drivers
<br />**Requires**:
- Windows 1903 insider preview 18317 or greater
- Windows Server 2019 / 1809 (RS5), with network policy limitations.<br /><br />**Note**: VXLAN runs on UDP port 4789 (this is the only port<br/>supported by Windows), remember to open that port
between your Calico hosts in any firewalls / security groups. |
| Static routes<br/>- Windows CNI plugin:
win-bridge.exe
- Linux: Calico policy-only | Simplest, but the most manual solution.                      |
| Cloud provider<br/>- Windows CNI plugin:
win-bridge.exe
- Linux: Calico policy-only | A useful fallback, particularly if you have a Kubernetes cloud<br/>provider that automatically installs inter-host routes. Calico
has been tested with the standard win-bridge.exe CNI
plugin so it should work with any networking provider that
ultimately uses win-bridge.exe to network the pod (such
as the Azure CNI plugin and cloud provider). |
| flannel host-gw<br/>Windows CNI plugin:
flannel.exe
Linux: Calico for policy and
flannel for networking | Automates programming of routes on Windows and Linux.<br/>Requires layer-2 adjacency between hosts (same subnet in
AWS).
**Note for AWS users**: If running on AWS, you must disable
the source/dest check on your EC2 instances so that hosts
can forward traffic on behalf of pods.<br /><br />**Note**: the provided manifests below install flannel on Linux
nodes using the Kubernetes API server as flannel's
datastore. This avoids the need to set up an additional etcd
server. |
| flannel vxlan                                                | Not yet tested with Windows<br/>nodes. |

### Review BGP limitations with Windows

If you are using Calico with BGP, note these current limitations with Windows.

| **Feature**                  | **Limitation**                                               |
| ---------------------------- | ------------------------------------------------------------ |
| IP mobility/borrowing        | Calico IPAM allocates IPs to host in blocks for aggregation<br/>purposes.<br />
If the IP pool is full, nodes can also "borrow" IPs from
another node's block. In BGP terms, the borrower then
advertises a more specific "/32" route for the borrowed IP
and traffic for that IP only is routed to the borrowing host.
(This also allows for IP mobility in the Calico OpenStack
integration.)
Windows nodes do not support this borrowing mechanism;
they will not borrow IPs even if the IP pool is full and they
mark their blocks so that Linux nodes will not borrow from
them. |
| IPs reserved for<br/>Windows | Calico IPAM allocates IPs in CIDR blocks. Due to networking<br/>requirements on Windows, four IPs per Windows
node-owned block must be reserved for internal purposes.
For example, with the default block size of /26, each block
contains 64 IP addresses, 4 are reserved for Windows,
leaving 60 for pod networking.
To reduce the impact of these reservations, a larger block
size can be configured at the IP pool scope (before any pods
are created). |
| Single IP block per host     | Calico IPAM is designed to allocate blocks of IPs (default size<br/>/26) to hosts on demand. While the Calico CNI plugin was
written to do the same, kube-proxy currently only supports a
single IP block per host.
Tigera is working with Microsoft to find a resolution.
To work around the default limit of one /26 per host there
are a couple of options:
- With Calico BGP networking and the etcd datastore:
before creating any blocks, change the block size
used by the IP pool so that it is sufficient for the
largest number of Pods that are to be used on a
single Windows host.
- Use Calico BGP networking with the kubernetes
datastore. In that mode, Calico IPAM is not used and
the CNI host-local IPAM plugin is used with the node's
Pod CIDR.
To allow multiple IPAM blocks per host (at the expense of
kube-proxy compatibility), set the
windows_use_single_network flag to false in the
cni.conf.template before installing Calico. Changing that
setting after pods have been networked is not
recommended since it may leak HNS endpoints |
| IPIP overlay                 | Tigera Calico's IPIP overlay mode cannot be used in clusters<br/>that contain Windows nodes. This is because Windows has
no support for IPIP. |
| NAT-outgoing                 | Calico IP pools support a "NAT outgoing" setting with the<br/>following behaviour:
- Traffic between Calico workloads (in any IP pools) is
not NATted |
| Service IP<br/>advertisement | This Calico v3.4+ feature is not supported on Windows.       |

### Determine datastore

| **Networking mode**     | **etcd datastore** support? | Kubernetes API datastore support? |
| ----------------------- | --------------------------- | --------------------------------- |
| Calico BGP              | Yes                         | Yes                               |
| Calico VXLAN            | Yes                         | Yes                               |
| flannel                 | No                          | Yes                               |
| static routes/other CNI | No                          | Yes                               |

Because Calico requires the same datastore to be used across the entire Kubernetes cluster, the same support applies to Linux nodes.  

### Next steps

You are now ready to:

-  Review [requirements]() 
- [Install Calico for Windows]()
