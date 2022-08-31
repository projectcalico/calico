---
title: Troubleshoot Calico for Windows
description: Help for troubleshooting Calico for Windows issues in Calico this release.
canonical_url: /getting-started/windows-calico/troubleshoot
---

### Useful troubleshooting commands

**Examine the HNS network(s)**

When using the {{site.prodname}} CNI plugin, each {{site.prodname}} IPAM block (or the single podCIDR in host-local IPAM mode), is represented as a HNS l2bridge network. Use the following command to inspect the networks.

```powershell
ipmo -DisableNameChecking {{site.rootDirWindows}}\libs\hns\hns.psm1
Get-HNSNetwork
```

**Examine pod endpoints**

Use the following command to view the HNS endpoints on the system. There should be one HNS endpoint per pod networked with {{site.prodname}}:

```powershell
ipmo -DisableNameChecking {{site.rootDirWindows}}\libs\hns\hns.psm1
Get-HNSEndpoint
```

### Troubleshoot

#### kubectl exec fails with timeout for Windows pods

Ensure that the Windows firewall (and any network firewall or cloud security group) allows traffic to the host on port 10250.

#### kubelet fails to register, complains of node not found in logs

This can be caused by a mismatch between a cloud provider (such as the AWS cloud provider) and the configuration of the node. For example, the AWS cloud provider requires that the node has a nodename matching its private domain name.

#### After initializing {{site.prodnameWindows}}, AWS metadata server is no longer reachable

This is a known Windows issue that Microsoft is working on. The route to the metadata server is lost when the vSwitch is created. As a workaround, manually add the route back by running:

```powershell
New-NetRoute -DestinationPrefix 169.254.169.254/32 -InterfaceIndex <interface-index>
```

Where <interface-index> is the index of the "vEthernet (Ethernet 2)" device as shown by

```powershell
Get-NetAdapter
```

#### Installation stalls at "Waiting for {{site.prodname}} initialization to finish"

This can be caused by Window's Execution protection feature. Exit the install using Ctrl-C, unblock the scripts, run `uninstall-calico.ps1`, followed by `install-calico.ps1`.

#### Windows Server 2019 insider preview: after rebooting a node, {{site.prodnameWindows}} fails to start, the tigera-node.err.log file contains errors

After rebooting the Windows node, pods fail to schedule, and the kubelet log has CNI errors like "timed out waiting for interface matching the management IP (169.254.57.5) of network" (where the IP address may vary but will always be a 169.254.x.x address). To workaround:

- Stop and then start {{site.prodnameWindows}} using the `stop-calico.ps1` and `start-calico.ps1` scripts
- Sometimes the HNS network picks up a temporary self-assigned address at start-of-day and it does not get refreshed when the correct IP becomes known. Rebooting the node a second time often resolves the problem.

#### Invoke-Webrequest fails with TLS errors

The error, "The request was aborted: Could not create SSL/TLS secure channel", often means that Windows does not support TLS v1.2 (which is required by many websites) by default. To enable TLS v1.2, run the following command:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

#### Kubelet persistently fails to contact the API server

If kubelet is already running when {{site.prodnameWindows}} is installed, the creation of the container vSwitch can cause kubelet to lose its connection and then persistently fail to reconnect to the API server.
To resolve this, restart kubelet after installing {{site.prodnameWindows}}.

#### No connectivity between pods on Linux and Windows nodes

If using AWS, check that the source/dest check is disabled on the interfaces assigned to your nodes. This allows nodes to forward traffic on behalf of local pods.
In AWS, the "Change Source/Dest. Check" option can be found on the Actions menu for a selected network interface.

If using {{site.prodname}} networking, check that the {{site.prodname}} IP pool you are using has IPIP mode disabled (set to "Never). IPIP is not supported on Windows. To check the IP pool, you can use `calicoctl`:

```bash
calicoctl get ippool -o yaml
```

Example output of an IP pool with IPIP disabled:

```
apiVersion: projectcalico.org/v3
items:
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
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

#### Felix log error: "Failed to create datastore client"

If the error includes 'loading config file "<path-to-kubeconfig>"', follow the instructions in
[Set environment variables]({{site.baseurl}}/getting-started/windows-calico/standard#install-calico-and-kubernetes-on-windows-nodes) to update the `KUBECONFIG` environment variable to the path of your kubeconfig file.

#### Felix starts, but does not output logs

By default, Felix waits to connect to the datastore before logging (in case the datastore configuration intentionally disables logging). To start logging at startup, update the [FELIX_LOGSEVERITYSCREEN environment variable]({{site.baseurl}}/reference/felix/configuration#general-configuration) to "info" or "debug" level.

#### {{site.prodname}} BGP mode: connectivity issues, Linux calico/node pods report unready

Check the detailed health output that shows which health check failed:

```
kubectl describe pod -n calico-system <calico-node-pod>
```

>**Note**: Use namespace `kube-system` instead of `calico-system` if your Calico installation is non operator-managed.
{: .alert .alert-info}


If the health check reports a BGP peer failure, check the IP address of the peer is either an
expected IP of a node or an external BGP peer. If the IP of the failed peering is a Windows node:

- Check that the node is up a reachable over IP
- Check that the RemoteAccess service is installed and running:

  ```powershell
  Get-Service | ? Name -EQ RemoteAccess
  ``` 
- Check the logs for the confd service in the configured log directory for errors
(default {{site.rootDirWindows}}\logs).

**Examine BGP state on a Windows host**

The Windows BGP router exposes its configuration and state as PowerShell commandlets.

**To show BGP peers**:

```powershell
Get-BgpPeer
```

Example output:

```
PeerName LocalIPAddress PeerIPAddress PeerASN OperationMode ConnectivityStatus
-------- -------------- ------------- ------- ------------- ------------------
Mesh_172_20_48_43 172.20.55.101 172.20.48.43 64512 Mixed Connected
Mesh_172_20_51_170 172.20.55.101 172.20.51.170 64512 Mixed Connected
Mesh_172_20_54_3 172.20.55.101 172.20.54.3 64512 Mixed Connected
Mesh_172_20_58_252 172.20.55.101 172.20.58.252 64512 Mixed Connected
For an established peering, the ConnectivityStatus column should be "Connected".
```

**To examine routes learned from other hosts**:

```powershell
Get-BgpRouteInformation -Type all
```

Example output:

```
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
```powershell
Restart-Service RemoteAccess
```

To see the routes being exported by this host:
```powershell
(Get-BgpCustomRoute).Network
```

Example output:
```
10.243.214.152/29
10.243.214.160/29
10.243.214.168/29
10.244.42.0/26
```
