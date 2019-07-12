---
title: Configuring MTU
canonical_url: 'https://docs.projectcalico.org/v3.7/networking/mtu'
---

Depending on the environment {{site.prodname}} is being deployed into it may be
helpful or even necessary to configure the MTU of the veth (or TAP) that is
attached to each workload and the tunnel devices if IP-in-IP is enabled.

### Selecting MTU size

Typically the MTU for your workload interfaces should match the network MTU.
If you need IP-in-IP then the MTU size for both the workload **and** tunnel
interfaces should be 20 bytes less than the network MTU for your network.
This is due to the extra 20 byte header that the tunnel will add to each
packet.

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
is 1440 to match the value needed in GCE.

#### Using flannel for networking

When using flannel for networking, the MTU for the network interfaces
should match the MTU of the flannel interface.  In the above table the 4th
column "{{site.prodname}} MTU with VXLAN" is the expected MTU when using flannel
configured with VXLAN.

## MTU configuration

CNI, which is used by Kubernetes and the Mesos Unified Containerizer, supports
configuring the MTU through the CNI configuration file.

The user will also want to configure {{site.prodname}}'s IP-in-IP interface MTU when
IP-in-IP is enabled on the cluster. Refer to the MTU table at the top of the page
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

Passing in the environment variable `FELIX_IPINIPMTU` when running the
`{{site.nodecontainer}}` container will set the MTU for Felix to use.

When using the Kubernetes self-hosted manifests, Felix derives this value from
the `veth_mtu` field of the calico-config ConfigMap, which is set to `1440` by default.

### Setting tunnel MTU with calicoctl

To set the IP-in-IP MTU value for all {{site.prodname}} nodes in your cluster, use the
following command to retrieve the current Felix settings.

```bash
calicoctl get felixconfig --export -o yaml > felix.yaml
```

Modify ipipMTU to the intended integer value.

```bash
vim felix.yaml
```

Replace the current felixconfig settings.

```bash
calicoctl replace -f felix.yaml
```

> **Note**: Setting the `ipipMTU` config option will result in an immediate
> update of the tunnel interface MTU on all of the active nodes in your cluster.
{: .alert .alert-info}
