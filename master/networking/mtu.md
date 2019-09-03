---
title: Configure MTU to maximize network performance
canonical_url: 'https://docs.projectcalico.org/v3.7/networking/mtu'
---

### Big picture

Configure the maximum transmission unit (MTU) for your {{site.prodname}} environment.

### Value

Optimize network performance for workloads by configuring the MTU in {{site.prodname}} to best suit your underlying network.

Increasing the MTU can improve performance, and decreasing the MTU when it is too high can resolve packet loss and fragmentation problems.

### Features

This how-to guide uses the following {{site.prodname}} features:

- calico-config file
- CNI configuration file
- Felix environment variables

### Concepts

#### MTU and {{site.prodname}} defaults

The maximum transmission unit (MTU) setting determines the largest packet size that can be transmitted through your network. MTU is configured on the veth attached to each workload, and tunnel devices (if you enable IP in IP and/or VXLAN).

The default MTU sizes are:

- Workloads (veth), 1440
- IP in IP (tunnel device), 1440
- VXLAN (tunnel device), 1410

In general, maximum performance is achieved by using the highest MTU value that does not cause fragmentation or drop packets on the path.  Maximum bandwidth increases, and CPU consumption for a given traffic rate may drop.  The improvement is often more significant when pod to pod traffic is being encapsulated (IP in IP or VXLAN), and splitting and combining such traffic cannot be offloaded to your NICs.

For example, if you are using AWS, you may be able to use jumbo frames up to 9000 bytes. If you are using {{site.prodname}} overlay networks, you may need to adjust the MTU settings to ensure packets aren’t lost or dropped from the size is being too high or too low.

### Before you begin...

For help using IP in IP and/or VXLAN overlays, see [Configure overlay networking]({{site.baseurl}}/{{page.version}}/networking/vxlan-ipip).

### How to

- [Determine MTU size](#determine-mtu- size)
- [Configure MTU for workloads](#configure-mtu-for-workloads)
- [Configure MTU for overlay networking](#configure-mtu-for-overlay-networking)

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

##### Recommended MTU for overlay networking

The extra overlay header used in IP in IP and VXLAN protocols, reduces the minimum MTU by the size of the header. (IP in IP uses a 20-byte header, and VXLAN uses a 50-byte header). Therefore, we recommend the following:

- If you use VXLAN anywhere in your pod network, configure MTU size as “physical network MTU size minus 50”. 
- If you use only IP in IP, configure MTU size as “physical network MTU size minus 20”
- Set the workload endpoint MTU and the tunnel MTUs to the same value (so all paths have the same MTU)

##### MTU for flannel networking

When using flannel for networking, the MTU for network interfaces should match the MTU of the flannel interface. If using flannel with VXLAN, use the “Calico MTU with VXLAN” column in the table above for common sizes. 

#### Configure MTU for workloads

When you set the MTU it applies to new workloads. To apply MTU changes to existing workloads, you must restart calico nodes. Restarting the calico/node pods also updates any {{site.prodname}} tunnel network interfaces on that node. 

**Configure MTU in calico-config**
  
Edit the `calico-config.yaml` file and update the veth value for your environment. For example:
  
`veth_mtu: “1440”`

**(Advanced) Configure MTU in the CNI configuration file**

If you are installing {{site.prodname}} using [{{site.prodname}} the hard way](https://docs.projectcalico.org/master/getting-started/kubernetes/hardway/), you can update the MTU directly in the CNI configuration file. For example:

```
{
   "name": "any_name",
    "cniVersion": "0.1.0",
   "type": "calico",
   "mtu": 1480,
   "ipam": {
     "type": "calico-ipam"
   }
}
```
>**Note**: When using Kubernetes self-hosted manifests, the CNI plugin gets the MTU value from the `veth_mtu` field of the calico-config ConfigMap, and is set to `1440` by default. On restart of the `{{site.nodecontainer}}` workloads, any references to `__CNI_MTU__` are replaced with the `veth_mtu` value and inserted into the CNI configuration file (aka conflist) at the directory specified by Kubernetes (currently defaults to `/etc/cni/net.d/`).
{: .alert .alert-info}

#### Configure MTU for overlay networking

If you are using IP in IP and/or VXLAN for Calico overlay networking, you must also set the tunnel MTU to match the value that you configured for the veth MTU. 

To view the existing tunnel size, use the command: 

`ip addr sh`

The IP in IP tunnel appears as tunlx (for example, tunl0), along with the MTU size. For example:

![Tunnel MTU]({{site.baseurl}}/images/tunnel.png)

##### Set tunnel MTU values

To set tunnel MTU for all calico nodes in a cluster, use one of the following methods:

- **Felix environment variables** 
  
  Pass the following environment variable(s)in the [Felix configuration file](https://docs.projectcalico.org/master/reference/resources/felixconfig):  
   - FELIX_IPINIPMTU
   - FELIX_VXLANMTU

- **felixconfig file**
  - Open the Felix configuration file.  
    `calicoctl get felixconfig default --export -o yaml > felix.yaml`
  - Change the MTU value for: ipipMTU and/or vxlanMTU   
    `vim felix.yaml`
  - Apply the new settings.  
    `calicoctl replace -f felix.yaml`

All active nodes in the cluster are updated immediately.