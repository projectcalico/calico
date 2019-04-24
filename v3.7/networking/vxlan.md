---
title: Configuring VXLAN
---

In addition to [IP-in-IP]({{site.baseurl}}/{{page.version}}/networking/ip-in-ip) overlay mode, {{site.prodname}} supports VXLAN
as an overlay protocol.  VXLAN has some trade-offs vs IP-in-IP; VXLAN is supported in some environments where 
IP-in-IP is not (such as Azure) but it has slightly higher per-packet overhead due to its larger header.

{{site.prodname}} can be configured to use VXLAN encapsulation by setting the `vxlanMode` option
on the [IP pool resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).
When enabled, {{site.prodname}} will use VXLAN encapsulation when routing packets *to*
workload IPs falling in the IP pool range.

### Enabling VXLAN for inter-workload traffic

With the VXLAN `vxlanMode` set to `Always`, {{site.prodname}} will route using VXLAN for
all traffic originating from a {{site.prodname}} enabled host to all {{site.prodname}} networked containers
and VMs within the IP Pool.

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 to use VXLAN with mode `Always`:

```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-vxlan-1
spec:
  cidr: 192.168.0.0/16
  vxlanMode: Always
  natOutgoing: true
EOF
```

> **Note**: In this release, `CrossSubnet` mode (as supported by IP-in-IP mode) is not supported for VXLAN.
>
> Switching to VXLAN mode can cause disruption to in-progress connections.
{: .alert .alert-info}

### Disabling BGP networking

When using only VXLAN pools BGP networking is not required.  If you wish to disable BGP entirely so that your cluster 
has one fewer moving parts, follow the instructions in [Customizing the manifests]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/config-options)
to set the `calico_backend` setting to `vxlan` and disable the BGP readiness check.

### See also

The [FelixConfiguration resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/felixconfig) contains 
further settings for VXLAN, including the virtual network ID, VXLAN port and tunnel MTU.

