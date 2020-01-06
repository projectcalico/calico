---
title: Configure MTU to maximize network performance
Description: Optimize network performance for workloads by configuring the MTU in Calico to best suit your underlying network.
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

The maximum transmission unit (MTU) setting determines the largest packet size that can be transmitted through your network. MTU is configured on the veth attached to each workload, and tunnel devices (if you enable IP in IP and/or VXLAN).

In general, maximum performance is achieved by using the highest MTU value that does not cause fragmentation or drop packets on the path.  Maximum bandwidth increases and CPU consumption may drop for a given traffic rate.  The improvement is often more significant when pod to pod traffic is being encapsulated (IP in IP or VXLAN), and splitting and combining such traffic cannot be offloaded to your NICs.

For example, if you are using AWS, you may be able to use jumbo frames up to 9000 bytes. If you are using {{site.prodname}} overlay networks, you may need to adjust the MTU settings to ensure packets aren’t lost or dropped from the size is being too high.

### Before you begin...

For help using IP in IP and/or VXLAN overlays, see [Configure overlay networking]({{ site.baseurl }}/networking/vxlan-ipip).

### How to

- [Determine MTU size](#determine-mtu-size)
- [Configure MTU for workloads](#configure-mtu-for-workloads)
- [Configure MTU for overlay networking](#configure-mtu-for-overlay-networking)
- [View current tunnel MTU values](#view-current-tunnel-mtu-values)

#### Determine MTU size

The following table lists common MTU sizes for {{site.prodname}} environments. Because MTU is a global property of the network path between endpoints, you should set the MTU to the minimum MTU of any path that packets may take. 

**Common MTU sizes**

| Network MTU            | {{site.prodname}} MTU | {{site.prodname}} MTU with IP-in-IP (IPv4) | {{site.prodname}} MTU with VXLAN (IPv4) |
| ---------------------- | --------------------- | ------------------------------------------ | --------------------------------------- |
| 1500                   | 1500                  | 1480                                       | 1450                                    |
| 9000                   | 9000                  | 8980                                       | 8950                                    |
| 1460 (GCE)             | 1460                  | 1440                                       | 1410                                    |
| 9001 (AWS Jumbo)       | 9001                  | 8981                                       | 8951                                    |
| 1450 (OpenStack VXLAN) | 1450                  | 1430                                       | 1400                                    |

**Recommended MTU for overlay networking**

The extra overlay header used in IP in IP and VXLAN protocols, reduces the minimum MTU by the size of the header. (IP in IP uses a 20-byte header, and VXLAN uses a 50-byte header). Therefore, we recommend the following:

- If you use VXLAN anywhere in your pod network, configure MTU size as “physical network MTU size minus 50”. 
- If you use only IP in IP, configure MTU size as “physical network MTU size minus 20”
- Set the workload endpoint MTU and the tunnel MTUs to the same value (so all paths have the same MTU)

**MTU for flannel networking**

When using flannel for networking, the MTU for network interfaces should match the MTU of the flannel interface. If using flannel with VXLAN, use the “{{site.prodname}} MTU with VXLAN” column in the table above for common sizes. 

#### Configure MTU for workloads
  
When you set the MTU, it applies to new workloads. To apply MTU changes to existing workloads, you must restart calico nodes. Restarting the calico/node pods takes values from the ConfigMap and starts rolling updates for any {{site.prodname}} tunnel network interfaces on the node. 

Edit the `calico-config` ConfigMap to set values in FelixConfiguration. For example:

```
kubectl patch configmap/{{site.prodname}}-config -n kube-system --type merge \
  -p '{"data":{"veth_mtu": "1440"}}'
```

#### Configure MTU for overlay networking

If you are using IP in IP and/or VXLAN for {{site.prodname}} overlay networking, set the tunnel MTU to match the value that you configured for the veth MTU. 

Edit `calico-config ConfigMap` to set the MTU tunnel values in FelixConfiguration. For example: 

```
# Configure the MTU to use
veth_mtu: "1440" 
```

#### View current tunnel MTU values

To view the current tunnel size, use the following command: 

`ip link show`

The IP in IP tunnel appears as tunlx (for example, tunl0), along with the MTU size. For example:

![Tunnel MTU]({{site.baseurl}}/images/tunnel.png)
