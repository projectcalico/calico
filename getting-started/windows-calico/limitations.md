---
title: Limitations and known issues
description: Review limitations before starting installation.
canonical_url: '/getting-started/windows-calico/limitations'
---

### Calico for Windows feature limitations

| **Feature** | **Not supported**                                            |
| ----------- | ------------------------------------------------------------ |
| Install     | Operator install                                             |
|             | AKS, GKE, IKS, AWS, GCE, Azure, OpenShift, OpenStack, flannel |
|             | K3 clusters                                                  |
| Security    | Non-cluster hosts, including automatic host endpoints        |
|             | Application layer policy (ALP) for Istio                     |
| Networking  | BGP peering                                                  |
|             | IP in IP overlay with BPG routing                            |
|             | Cross-subnet support and MTU setting for VXLAN               |
|             | Service IP advertisement                                     |
|             | IPv6 and dual stack                                          |

### Networking limitations with {{site.prodname}} VXLAN 

Because of differences between the Linux and Windows dataplane feature sets, the following {{site.prodname}} features are not supported on Windows.

| Feature                  | Limitation                                                   |
| ------------------------ | ------------------------------------------------------------ |
| IPs reserved for Windows | {{site.prodname}} IPAM allocates IPs in CIDR blocks. Due to networking requirements on Windows, four IPs per Windows node-owned block must be reserved for internal purposes.<br /><br/>For example, with the default block size of /26, each block contains 64 IP addresses, 4 are reserved for Windows, leaving 60 for pod networking.<br /><br />To reduce the impact of these reservations, a larger block size can be configured at the IP pool scope (before any pods are created). |
| Single IP block per host | {{site.prodname}} IPAM is designed to allocate blocks of IPs (default size /26) to hosts on demand. While the {{site.prodname}} CNI plugin was written to do the same, kube-proxy currently only supports a single IP block per host. <br />To allow multiple IPAM blocks per host (at the expense of kube-proxy compatibility), set the `windows_use_single_network` flag to `false` in the `cni.conf.template` before installing {{site.prodname}}. Changing that setting after pods are networked is not recommended because it may leak HNS endpoints. |
| NAT-outgoing             | {{site.prodname}} IP pools support a "NAT outgoing" setting with the following behaviour: <br /><br />- Traffic between {{site.prodname}} workloads (in any IP pools) is not NATted. <br />- Traffic leaving the configured IP pools is NATted if the workload has an IP within an IP pool that has NAT outgoing enabled. {{ site.prodNameWindows }} honors the above setting but it is only applied at pod creation time. If the IP pool configuration is updated after a pod is created, the pod's traffic will continue to be NATted (or not) as before. NAT policy for newly-networked pods will honor the new configuration. {{ site.prodNameWindows }} automatically adds the host itself and its subnet to the NAT exclusion list. This behaviour can be disabled by setting flag `windows_disable_host_subnet_nat_exclusion` to `true` in `cni.conf.template` before running the install script. |

### Routes are lost in cloud providers

If you create a Windows host with a cloud provider (AWS for example), the creation of the vSwitch at {{site.prodname}} install time can remove the cloud provider's metadata route. If your application relies on the metadata service, you may need to examine the routing table before and after installing {{site.prodname}} in order to reinstate any lost routes.

**VXLAN limitations**

**VXLAN support**

- Windows 1903 build 18317 and above
- Windows 1809 build 17763 and above

**Configuration updates**

Certain configuration changes will not be honored after the first pod is networked. This is because Windows does not currently support updating the VXLAN subnet parameters after the network is created so updating those parameters requires the node to be drained:

One example is the VXLAN VNI setting. To change such parameters:
- Drain the node of all pods
- Delete the {{site.prodname}} HNS network:

   ```
   PS C:\> Import-Module C:\CalicoWindows\libs\hns\hns.psm1
   PS C:\> Get-HNSNetwork | ? Name -EQ "{{site.prodname}}" | Remove-HNSNetwork
   ```
- Update the configuration in `config.ps1`, run `uninstall-calico.ps1` and then `install-calico.ps1` to regenerate the CNI configuration.

### Pod-to-pod connections are dropped with TCP reset packets

Restarting Felix or changes to policy (including changes to endpoints referred to in policy), can cause pod-to-pod connections to be dropped with TCP reset packets. When one of the following occurs:

- The policy that applies to a pod is updated
- Some ingress or egress policy that applies to a pod contains selectors and the set of endpoints that those selectors match changes,

Felix must reprogram the HNS ACL policy attached to the pod. This reprogramming can cause TCP resets.

Microsoft has confirmed this is a HNS issue, and they are investigating.

### Service ClusterIPs incompatible with selectors/pod IPs in network policy

**Windows 1809 and 1903 prior to build 18317**

On Windows nodes, kube-proxy unconditionally applies source NAT to traffic from local pods to service ClusterIPs. This means that, at the destination pod, where policy is applied, the traffic appears to come from the source host rather than the source pod. In turn, this means that a network policy with a source selector matching the source pod will not match the expected traffic.

### Network policy and using selectors

Under certain conditions, relatively simple {{site.prodname}} policies can require significant Windows dataplane resources, that can cause significant CPU and memory usage, and large policy programming latency.

We recommend avoiding policies that contain rules with both a source and destination selector. The following is an example of a policy that would be inefficient. The policy applies to all workloads, and it only allows traffic from workloads labeled as clients to workloads labeled as servers:

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
Because the policy applies to all workloads, it will be rendered once per workload (even if the workload is not labeled as a server), and then the selectors will be expanded into many individual dataplane rules to capture the allowed connectivity. 

Here is a much more efficient policy that still allows the same traffic:

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
The destination selector is moved into the policy selector, so this policy is only rendered for workloads that have the role: `webserver` label. In addition, the rule is simplified so that it only matches on the source of the traffic. Depending on the number of webserver pods, this change can reduce the dataplane resource usage by several orders of magnitude.

### Next steps

- [Quickstart]({{site.baseurl}}/getting-started/windows-calico/quickstart)
- [Standard install]({{site.baseurl}}/getting-started/windows-calico/standard)
