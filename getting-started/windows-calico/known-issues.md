---
title: Known issues with Calico for Windows
description: Review known issues and limitations for Calico for Windows
canonical_url: 
---

#### Pod-to-pod connections are dropped with TCP reset packets

Restarting Felix or changes to policy (including changes to endpoints referred to in policy), can cause pod-to-pod connections to be dropped with TCP reset packets. When one of the following occurs:
- The policy that applies to a pod is updated
- Some ingress or egress policy that applies to a pod contains selectors and the set of endpoints that those selectors match changes,

Felix must reprogram the HNS ACL policy attached to the pod. This reprogramming can cause TCP resets.

Microsoft has confirmed this is a HNS issue, and they are investigating.

#### Windows 1809 and 1903 prior to build 18317: Service ClusterIPs incompatible with selectors/pod IPs in network policy

On Windows nodes, kube-proxy unconditionally applies source NAT to traffic from local pods to service ClusterIPs. This means that, at the destination pod, where policy is applied, the traffic appears to come from the source host rather than the source pod. In turn, this means that a network policy with a source selector matching the source pod will not match the expected traffic.

#### Calico BGP networking limitations

| **User**                 | **Permissions**                                              |
| ------------------------ | ------------------------------------------------------------ |
| IP mobility/borrowing    | Calico IPAM allocates IPs to host in blocks for aggregation<br/>purposes.
If the IP pool is full, nodes can also "borrow" IPs from another node's block. In BGP terms, the borrower then advertises a more specific "/32" route for the borrowed IP and traffic for that IP only is routed to the borrowing host.
(This also allows for IP mobility in the Calico OpenStack integration.) |
| IPs reserved for Windows | Calico IPAM allocates IPs in CIDR blocks. Due to networking<br/>requirements on Windows, four IPs per Windows node-owned block must be reserved for internal purposes.<br /><br />For example, with the default block size of /26, each block contains 64 IP addresses, 4 are reserved for Windows, leaving 60 for pod networking.<br /><br />
To reduce the impact of these reservations, a larger block size can be configured at the IP pool scope (before any pods are created). |
| Single IP block per host | Calico IPAM is designed to allocate blocks of IPs (default size /26) to hosts on demand. While the Calico CNI plugin was written to do the same, kube-proxy currently only supports a single IP block per host.<br /><br />
Tigera is working with Microsoft to find a resolution.
To work around the default limit of one /26 per host there are a few options:
- With Calico BGP networking and the etcd datastore:
before creating any blocks, change the block size
used by the IP pool so that it is sufficient for the
largest number of Pods that are to be used on a
single Windows host.
- Use Calico BGP networking with the kubernetes
datastore. In that mode, Calico IPAM is not used and
the CNI host-local IPAM plugin is used with the node's
Pod CIDR.<br /><br />
To allow multiple IPAM blocks per host (at the expense of
kube-proxy compatibility), set the
windows_use_single_network flag to false in the
cni.conf.template before installing Calico. Changing that
setting after pods have been networked is not
recommended since it may leak HNS endpoints |
| IPIP overlay             | Tigera Calico's IPIP overlay mode cannot be used in clusters<br/>that contain Windows nodes. This is because Windows has
no support for IPIP. |
| NAT-outgoing             | Calico IP pools support a "NAT outgoing" setting with the following behaviour:
- Traffic between Calico workloads (in any IP pools) is not NATted.
- Traffic leaving the configured IP pools is NATted if the workload has an IP within an IP pool that has NAT outgoing enabled.<br /><br />
Tigera Calico for Windows honors the above setting but it is only applied at pod creation time. If the IP pool configuration is updated after a pod is created, the pod's traffic will continue to be NATted (or not) as before. NAT policy for newly networked pods will honor the new configuration.<br /><br />
Tigera Calico for Windows automatically adds the host itself and its subnet to the NAT exclusion list. This behaviour can be disabled by setting flag windows_disable_host_subnet_nat_exclusion to true in cni.conf.template before running the install script. |
| Service IP advertisement | This feature is not supported on Windows.       |

#### Network policy limitations

Because of differences between the Linux and Windows dataplane feature sets, some Calico features are not supported on Windows.

| **Feature**                     | **Notes**                                                    |
| ------------------------------- | ------------------------------------------------------------ |
| IPv6                            | IPv6 is not supported on Windows. Any IPv6-specific policy will be ignored. |
| Application Layer Policy        | Matching on HTTP fields and paths and service account<br/>credentials (via the integration with Envoy) is not supported. |
| Negated match criteria          | The negated variants of rule match criteria are not supported. Any rules that contain negated match criteria will be skipped and Felix will log a warning. In Calico network policies, the negated match criteria are prefixed with "not": "notProtocol", "notNets", "notSelector", "notPorts", and, "notICMP". |
| ICMP type/code matches          | While matching ICMP packets by protocol is supported, matching on the precise ICMP type and code are not supported. Felix will ignore rules with ICMP type/code matches with a warning. |
| "Pass" action not<br/>supported | Rules containing the "Pass" action are skipped on Windows. This is because "Pass" requires some way to "skip ahead" to a later rule, which is not supported in the Windows
dataplane. |

#### Network policy efficiency

Calico v3.4+ uses new features of the Windows dataplane released in 1803/RS4 to significantly improve the worst-case performance in the cases described below. However, the general advice on how to use selectors efficiently still applies:

Under certain conditions, relatively simple Calico policies can require significant Windows dataplane resources to represent, causing significant CPU and memory usage and large policy programming latency.

We recommends avoiding policies that contain rules with both a source and destination selector. For example, the following (fairly contrived) policy applies to all workloads, but then it only allows traffic from workloads labeled as clients to workloads labeled as servers:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
name: calico-dest-selector
spec:
selector: all()
order: 500
ingress:
- action: Allow
destination:
selector: role == "webserver"
source:
selector: role == "client"
```
Because the policy applies to all workloads, it will be rendered once per workload (even if the workload is not labeled as a server), and then the selectors will be expanded into many individual dataplane rules in order to capture the allowed connectivity. 

A much more efficient policy that still allows the same traffic is as follows:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
name: calico-dest-selector
spec:
selector: role == "webserver"
order: 500
ingress:
- action: Allow
source:
selector: role == "client"
```
The destination selector has been moved into the policy selector, so this policy will only be rendered for workloads that have the role: webserver label. In addition, the rule has been simplified so that it only matches on the source of the traffic. Depending on the number of webserver pods, this change may reduce the dataplane resource usage by several orders of magnitude.

Tigera is working with Microsoft to provide additional dataplane features that will improve performance and efficiency.

#### HNS endpoints leaked after pod scheduling failure on Windows

With Kubernetes v1.11.2, we observed leaked HNS endpoints on Windows after a pod scheduling failure (for example, trying to schedule a Linux pod to a Windows node). This was fixed in v1.11.3.

Kubernetes issue: https://github.com/kubernetes/kubernetes/issues/68511

#### Routes are lost in cloud providers

If you create a Windows host with a cloud provider (AWS for example), the creation of the vSwitch at Calico install time can remove the cloud provider's metadata route. If your application relies on the metadata service, you may need to examine the routing table before and after installing Calico in order to reinstate any lost routes.

**VXLAN limitations**

**VXLAN support**

- Windows 1903 build 18317 and above
- Windows 1809 build 17763 and above

**Configuration updates**

Certain configuration changes will not be honored after the first pod is networked. This is because Windows does not currently support updating the VXLAN subnet parameters after the network is created so updating those parameters requires the node to be drained:

For example the VXLAN VNI setting. To change such parameters:
- Drain the node of all pods
- Delete the Calico HNS network:

   ```
   PS C:\> Import-Module C:\TigeraCalico\libs\hns\hns.psm1
   PS C:\> Get-HNSNetwork | ? Name -EQ "Calico" | Remove-HNSNetwork
   ```
- Update the configuration in `config.ps1`, run `uninstall-calico.ps1` and then `install-calico.ps1` to regenerate the CNI configuration.

**No support for setting MTU**

On Windows, the VXLAN MTU is derived from the host's interface MTU so Calico cannot control it.

**No support for cross-subnet VXLAN**

On Windows, VXLAN encapsulation is not supported.

#### Kubernetes-hosted install 

Windows does not support privileged containers at this time. On Windows, Calico must be installed manually rather than as a Kubernetes-managed DaemonSet.
