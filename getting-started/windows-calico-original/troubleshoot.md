---
title: Troubleshoot Tigera Calico for Windows
description: 
canonical_url: 
---

### Useful troubleshooting commands

**Examine the HNS network(s)**

When using the Calico CNI plugin, each Calico IPAM block (or the single podCIDR in host-local IPAM mode), is represented as a HNS l2bridge network. The networks can be inspected with:

```
PS C:\> ipmo c:\TigeraCalico\libs\hns\hns.psm1
PS C:\> Get-HNSNetwork
```
**Examine pod endpoints**

Use the following command to view the HNS endpoints on the system. There should be one HNS endpoint per pod networked with Calico:

```
PS C:\> ipmo c:\TigeraCalico\libs\hns\hns.psm1
PS C:\> Get-HNSEndpoint
```

### Troubleshooting

#### kubectl exec fails with timeout for Windows pods

Ensure that the Windows firewall (and any network firewall or cloud security group) allows traffic to the host on port 10250.

#### kubelet fails to register, complains of node not found in logs

This can be caused by a mismatch between a cloud provider (such as the AWS cloud provider) and the configuration of the node. For example, the AWS cloud provider requires that the node has a nodename matching its private domain name.

#### After initialising Calico, AWS metadata server is no longer reachable

This is a known Windows issue that Microsoft are working on. The route to the metadata server is lost when the vSwitch is created. As a workaround, the route can be added back manually by running:

```
PS C:\> New-NetRoute -DestinationPrefix 169.254.169.254/32
-InterfaceIndex <interface-index>
```

Where <interface-index> is the index of the "vEthernet (Ethernet 2)" device as shown by

```
PS C:\> Get-NetAdapter
```
#### Installation stalls at "Waiting for Calico initialisation to finish"

This can be caused by Window's Execution protection feature. Exit the install using Ctrl-C, unblock the scripts, and then run uninstall-calico.ps1 followed by install-calico.ps1.

#### Windows Server 2019 insider preview: after rebooting a node, Calico fails to start, the tigera-node.err.log file contains errors.

Tigera believe that we understand this issue and we plan to resolve it in a patch release. As a workaround, stop and then start Calico using the stop-calico.ps1 and start-calico.ps1 scripts.

After reboot of Windows node, pods fail to schedule, kubelet log has CNI errors "timed out waiting for interface matching the management IP (169.254.57.5) of network" (where the IP address may vary but will always be a 169.254.x.x address)

Sometimes the HNS network picks up a temporary self-assigned address at start-of-day and it does not get refreshed when the correct IP becomes known. Tigera is working with Microsoft to diagnose this issue. As a workaround, rebooting the node a second time often resolves the problem.

#### Invoke-Webrequest fails with TLS errors

If you see an error such as "The request was aborted: Could not create SSL/TLS secure channel", the issue is often that Windows does not support TLS v1.2 (which is required by many websites) by default. To enable TLS v1.2, run the following command:

```
PS C:\> [Net.ServicePointManager]::SecurityProtocol = `
[Net.SecurityProtocolType]::Tls12
```
#### Kubelet persistently fails to contact the API server

If kubelet is already running when Calico is installed, the creation of the container vSwitch can cause kubelet to lose its connection and then persistently fail to reconnect to the API server. To resolve this, restart kubelet after installing Calico.

#### No connectivity between pods on Linux and Windows nodes

If using AWS, check that the source/dest check is disabled on the interfaces assigned to your nodes. This allows nodes to forward traffic on behalf of local pods. In AWS, the "Change Source/Dest. Check" option can be found on the Actions menu for a selected network interface.

If using Calico networking check that the Calico IP pool you are using has IPIP mode disabled. IPIP is not supported on Windows. To check the IP pool, you can use calicoctl:

```
$ calicoctl get ippool -o yaml
apiVersion: projectcalico.org/v3
items:
- apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
28
creationTimestamp: 2018-11-26T15:37:39Z
name: default-ipv4-ippool
resourceVersion: "172"
uid: 34db7316-f191-11e8-ad7d-02850eebe6c4
spec:
blockSize: 26
cidr: 192.168.0.0/16
disabled: true
ipipMode: Never
natOutgoing: true
```
The ipipMode setting should be "Never". To change the value, follow the instructions in this section.

#### Felix logs "Failed to create datastore client"

If the error includes 'loading config file "<path-to-kubeconfig>"', follow the instructions in
Changing environment variables to update the KUBECONFIG environment variable to the
path of your kubeconfig file.

#### Felix starts but logs no output

At its default log level Felix waits to connect to the datastore before logging (in case the datastore contains configuration that intentionally disables logging). To diagnose issues in early startup, follow the instructions in Updating Configuration to update the FELIX_LOGSEVERITYSCREEN environment variable to "info" or "debug" level.

#### DNS fails (possibly intermittently) in Windows pods

First, make sure the cumulative updates to August 2018 are installed, there were known DNS issues in earlier releases.
Some Windows container images suffer from intermittent DNS resolution failure (independent of Tigera Calico). If you experience that problem, adding the following lines to the Dockerfile for a Windows container image should work around the problem. Microsoft is aware of the issue and they are investigating.

```
RUN powershell New-ItemProperty -Path
'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
-Name MaxCacheTtl -Value 0 -Type DWord
RUN powershell Set-ItemProperty -path
'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
-Name MaxNegativeCacheTtl -Value 0 -Type DWord
```
#### Calico BGP mode: connectivity issues, Linux calico/node pods report unready

Check the detailed health output, which should explain which health check has failed:

```
kubectl describe pod -n kube-system <calico-node-pod>
```

If the health check reports a BGP peer failure, check the IP address of the peer is either an
expected IP of a node or an external BGP peer. If the IP of the failed peering is a Windows node,
- Check that the node is up a reachable over IP.
- Check that the RemoteAccess service is installed and running:
  ```
   PS C:\> Get-Service | ? Name -EQ RemoteAccess
  ``` 
- Check the logs for the confd service in the configured log directory for errors
(default C:\TigeraCalico\logs).

#### Examining BGP state on a Windows host

The Windows BGP router exposes its configuration and state as Powershell commandlets.

**To show BGP peers**:

```
PS C:\> Get-BgpPeer
PeerName LocalIPAddress PeerIPAddress PeerASN OperationMode ConnectivityStatus
-------- -------------- ------------- ------- ------------- ------------------
Mesh_172_20_48_43 172.20.55.101 172.20.48.43 64512 Mixed Connected
Mesh_172_20_51_170 172.20.55.101 172.20.51.170 64512 Mixed Connected
Mesh_172_20_54_3 172.20.55.101 172.20.54.3 64512 Mixed Connected
Mesh_172_20_58_252 172.20.55.101 172.20.58.252 64512 Mixed Connected
For an established peering, the ConnectivityStatus column should be "Connected".
```
**To examine routes learned from other hosts**:
```
PS C:\> Get-BgpRouteInformation -Type all
DestinationNetwork NextHop LearnedFromPeer State LocalPref MED
------------------ ------- --------------- ----- --------- ---
10.243.128.192/26 172.20.58.252 Mesh_172_20_58_252 Best 100
10.244.115.128/26 172.20.48.43 Mesh_172_20_48_43 Best 100
10.244.128.192/26 172.20.58.252 Mesh_172_20_58_252 Best 100
```
For active routes, the State should show as "Best". Routes with State equal to "Unresolved"
indicate that the BGP router could not resolve a route to the peer and the route will not be
used. This can occur if the networking state changes after the BGP router is started;
restarting the BGP router may solve the problem:
```
PS C:\> Restart-Service RemoteAccess
```
To see the routes being exported by this host:
```
PS C:\> (Get-BgpCustomRoute).Network
10.243.214.152/29
10.243.214.160/29
10.243.214.168/29
10.244.42.0/26
```
