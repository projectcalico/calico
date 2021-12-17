---
title: Configure MTU to maximize network performance
description: Optimize network performance for workloads by configuring the MTU in Calico to best suit your underlying network.
canonical_url: '/networking/mtu'
---

### Big picture

Configure the maximum transmission unit (MTU) for your {{site.prodname}} environment.

### Value

Optimize network performance for workloads by configuring the MTU in {{site.prodname}} to best suit your underlying network.

Increasing the MTU can improve performance, and decreasing the MTU can resolve packet loss and fragmentation problems when it is too high.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **FelixConfiguration** resource

### Concepts

#### MTU and {{site.prodname}} defaults

The maximum transmission unit (MTU) setting determines the largest packet size that can be transmitted through your network. MTU is configured on the veth attached to each workload, and tunnel devices (if you enable IP in IP, VXLAN, or WireGuard).

In general, maximum performance is achieved by using the highest MTU value that does not cause fragmentation or dropped packets on the path. Maximum bandwidth increases and CPU consumption may drop for a given traffic rate.  The improvement is often more significant when pod to pod traffic is being encapsulated (IP in IP, VXLAN, or WireGuard), and splitting and combining such traffic cannot be offloaded to your NICs.

By default, {{site.prodname}} will auto-detect the correct MTU for your cluster based on node configuration and enabled networking modes. This guide explains how you can override auto-detection
of MTU by providing an explicit value if needed.

To ensure auto-detection of MTU works correctly, make sure that the correct encapsulation modes are set in your [felix configuration]({{site.baseurl}}/reference/resources/felixconfig). Disable any unused encapsulations (`vxlanEnabled`, `ipipEnabled`, and `wireguardEnabled`) in your felix configuration to ensure that auto-detection can pick the optimal MTU for your cluster.

### Before you begin...

For help on using IP in IP and/or VXLAN overlays, see [Configure overlay networking]({{ site.baseurl }}/networking/vxlan-ipip).

For help on using WireGuard encryption, see [Configure WireGuard encryption]({{ site.baseurl }}/security/encrypt-cluster-pod-traffic).

### How to

- [Determine MTU size](#determine-mtu-size)
- [Configure MTU](#configure-mtu)
- [View current tunnel MTU values](#view-current-tunnel-mtu-values)

#### Determine MTU size

The following table lists common MTU sizes for {{site.prodname}} environments. Because MTU is a global property of the network path between endpoints, you should set the MTU to the minimum MTU of any path that packets may take.

**Common MTU sizes**

| Network MTU            | {{site.prodname}} MTU | {{site.prodname}} MTU with IP-in-IP (IPv4) | {{site.prodname}} MTU with VXLAN (IPv4) | {{site.prodname}} MTU with WireGuard (IPv4) |
| ---------------------- | --------------------- | ------------------------------------------ | --------------------------------------- | ------------------------------------------- |
| 1500                   | 1500                  | 1480                                       | 1450                                    | 1440                                        |
| 9000                   | 9000                  | 8980                                       | 8950                                    | 8940                                        |
| 1500 (AKS)             | 1500                  | 1480                                       | 1450                                    | 1340                                        |
| 1460 (GCE)             | 1460                  | 1440                                       | 1410                                    | 1400                                        |
| 9001 (AWS Jumbo)       | 9001                  | 8981                                       | 8951                                    | 8941                                        |
| 1450 (OpenStack VXLAN) | 1450                  | 1430                                       | 1400                                    | 1390                                        |

**Recommended MTU for overlay networking**

The extra overlay header used in IP in IP, VXLAN and WireGuard protocols, reduces the minimum MTU by the size of the header. (IP in IP uses a 20-byte header, VXLAN uses a 50-byte header, and WireGuard uses a {% include open-new-window.html text='60-byte header' url='https://lists.zx2c4.com/pipermail/wireguard/2017-December/002201.html' %}).

When using AKS, the underlying network has an {% include open-new-window.html text='MTU of 1400' url='https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-tcpip-performance-tuning#azure-and-vm-mtu' %}, even though the network interface will have an MTU of 1500.
WireGuard sets the Don't Fragment (DF) bit on its packets, and so the MTU for WireGuard on AKS needs to be set to 60 bytes below the 1400 MTU of the underlying network to avoid dropped packets.

If you have a mix of Wireguard and either IP in IP or VXLAN in your cluster, you should configure the MTU to be the smallest of the values of each encap type. This could be the case if, for example, you are in the process of installing WireGuard on your nodes.

Therefore, we recommend the following:

- If you use WireGuard encryption anywhere in your pod network, configure MTU size as “physical network MTU size minus 60”.
- If you don't use WireGuard, but use VXLAN anywhere in your pod network, configure MTU size as “physical network MTU size minus 50”.
- If you don't use WireGuard, but use only IP in IP, configure MTU size as “physical network MTU size minus 20”
- Set the workload endpoint MTU and the tunnel MTUs to the same value (so all paths have the same MTU)

**eBPF mode**

Implementation of NodePorts uses VXLAN tunnel to hand off packets from one node to another, therefore VXLAN MTU setting
is used to set the MTUs of workloads (veths) and should be “physical network MTU size minus 50” (see above).

**MTU for flannel networking**

When using flannel for networking, the MTU for network interfaces should match the MTU of the flannel interface.
- If using flannel with VXLAN, use the “{{site.prodname}} MTU with VXLAN” column in the table above for common sizes.

#### Configure MTU

> **Note**: The updated MTU used by {{site.prodname}} only applies to new workloads.

Select the appropriate instructions for configuring the MTU.  This is broken down based on installation:
-  Manifest based installation (if you are not using the quickstart guide, most non-OpenShift installs fall under this
   category)
-  Operator

##### **Manifest**

For manifest based installations (i.e. ones that do not use the operator) edit the `calico-config` ConfigMap. For example:

```bash
kubectl patch configmap/calico-config -n kube-system --type merge \
  -p '{"data":{"veth_mtu": "1440"}}'
```

After updating the ConfigMap, perform a rolling restart of all calico/node pods. For example:

```bash
kubectl rollout restart daemonset calico-node -n kube-system
```

##### **Operator**

For Operator installations, edit the {{site.prodname}} operator `Installation` resource to set the `mtu`
field in the `calicoNetwork` section of the `spec`.  For example:

```bash
kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"mtu":1440}}}'
```

Similarly, for OpenShift:

```bash
oc patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"mtu":1440}}}'
```

#### View current tunnel MTU values

To view the current tunnel size, use the following command:

`ip link show`

The IP in IP tunnel appears as tunlx (for example, tunl0), along with the MTU size. For example:

![Tunnel MTU]({{site.baseurl}}/images/tunnel.png)
