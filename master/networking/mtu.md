---
title: Configuring MTU
canonical_url: 'https://docs.projectcalico.org/v3.5/usage/configuration/mtu'
---

Depending on the environment {{site.prodname}} is being deployed into it may be
helpful or even necessary to configure the MTU of the veth (or TAP) that is
attached to each workload and the tunnel devices if IP-in-IP or VXLAN is enabled.

### Selecting MTU size

Since MTU is a global property of the network path between endpoints, the MTU for 
workloads needs to be set to the minimum MTU of any path that packets may take.

If you are using an overlay such as IP-in-IP or VXLAN, the extra overlay header
used by those protocols reduces the MTU by the size of the header.  IP-in-IP uses
a 20-byte header, VXLAN uses a 50-byte header.  Hence,

- If you use VXLAN anywhere in your pod network, you should select an MTU which is
  network MTU minus 50.
- If you do not use VXLAN but you do use IP-in-IP, you should select an MTU which is
  network MTU minus 20.
  
You should set the workload endpoint MTU **and** the tunnel MTUs to the same value.
This is so that all paths have the same MTU.

#### Common MTU sizes

| Network MTU | {{site.prodname}} MTU | {{site.prodname}} MTU with IP-in-IP | {{site.prodname}} MTU with VXLAN (IPv4) |
|-------------|------------|--------------------------|------------------------------|
| 1500 | 1500 | 1480 | 1450 |
| 9000 | 9000 | 8980 | 8950 |
| 1460 (GCE) | 1460 | 1440 | 1410 |
| 9001 (AWS Jumbo) | 9001 | 8981 | 8951 |
| 1450 (OpenStack VXLAN) | 1450 | 1430 | 1400 |

#### Default MTU sizes

The default MTU for workload interfaces is 1500, this is to match the most
common network MTU size. The default MTU for the IP-in-IP tunnel device
is 1440 to match the value needed in GCE.  Similarly, the default for VXLAN
is 1410.

#### Using flannel for networking

When using flannel for networking, the MTU for the network interfaces
should match the MTU of the flannel interface.  In the above table the 4th
column "{{site.prodname}} MTU with VXLAN" is the expected MTU when using flannel
configured with VXLAN.

## MTU configuration

It is the job of the network plugin to create new interfaces.  The CNI plugin, which is used by
Kubernetes, supports configuring the MTU of the workload interface through the CNI configuration file.

The user will also want to configure {{site.prodname}}'s IP-in-IP/VXLAN interface MTU when
IP-in-IP/VXLAN is enabled on the cluster. Refer to the MTU table at the top of the page
to choose the value that matches your environment.

> **Note**: The MTU on existing workloads will not be updated with these changes. To update
workload MTUs, see the section that corresponds to your plugin type.
{: .alert .alert-info}

### MTU configuration with CNI

MTU is set in the by the `"mtu": <MTU size>` field of the CNI configuration. Example:

```json
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

> **Note**: If using Kubernetes self-hosted manifests, you should modify the
`veth_mtu` value in the {{site.prodname}} ConfigMap instead, and leave `"mtu"` here
set to `__CNI_MTU__`. See below for more details.
{: .alert .alert-info}

### MTU configuration with Kubernetes self-hosted manifests

When using Kubernetes self-hosted manifests, the CNI plugin derives the MTU value
from the `veth_mtu` field of the calico-config ConfigMap, and it is set to `1440`
by default. On restart of the `{{site.nodecontainer}}` pods, any references to
`__CNI_MTU__` are replaced by the `veth_mtu` value and inserted into the CNI
configuration file (aka conflist) at the directory specified by Kubernetes
(currently defaults to `/etc/cni/net.d/`).

Restarting the `{{site.nodecontainer}}` pods will also update any {{site.prodname}}
tunnel network interfaces on that node. From this point forward, any pods
started will also have the updated MTU value.

### Setting tunnel MTU with a Felix environment variable

Passing in the environment variable `FELIX_IPINIPMTU` (or `FELIX_VXLANMTU`) when running the
`{{site.nodecontainer}}` container will set the MTU for Felix to use.

When using the Kubernetes self-hosted manifests, Felix derives the IP-in-IP value from
the `veth_mtu` field of the calico-config ConfigMap, which is set to `1440` by default.

### Setting tunnel MTU with calicoctl

To set the IP-in-IP MTU value for all {{site.prodname}} nodes in your cluster, use the
following command to retrieve the current Felix settings.

```bash
calicoctl get felixconfig default --export -o yaml > felix.yaml
```

Modify ipipMTU (or vxlanMTU) to the intended integer value.

```bash
vim felix.yaml
```

Replace the current felixconfig settings.

```bash
calicoctl replace -f felix.yaml
```

> **Note**: Setting the `ipipMTU` (of `vxlanMTU`) config option will result in an immediate
> update of the tunnel interface MTU on all of the active nodes in your cluster.
{: .alert .alert-info}
