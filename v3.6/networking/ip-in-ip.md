---
title: Configuring IP-in-IP
redirect_from: latest/networking/ip-in-ip
canonical_url: 'https://docs.projectcalico.org/v3.5/usage/configuration/ip-in-ip'
---

If your network fabric performs source/destination address checks
and drops traffic when those addresses are not recognized, it may be necessary to
enable IP-in-IP encapsulation of the inter-workload traffic.

This is often the case for public-cloud environments where you have limited control
over the network, and in particular you have no option to set up BGP peering between
your {{site.prodname}} nodes and the network routers.

{{site.prodname}} can be configured to use IP-in-IP encapsulation by enabling the IPIP option
on the [IP pool resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).
When enabled, {{site.prodname}} will use IP-in-IP encapsulation when routing packets *to*
workload IPs falling in the IP pool range.

An optional `ipipMode` field toggles when IP-in-IP is used, see following sections for
details.

### Configuring IP-in-IP for all inter-workload traffic

With the IP-in-IP `ipipMode` set to `Always`, {{site.prodname}} will route using IP-in-IP for
all traffic originating from a {{site.prodname}} enabled host to all {{site.prodname}} networked containers
and VMs within the IP Pool.

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 to use IP-in-IP with mode `Always`:

```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-ipip-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: Always
  natOutgoing: true
EOF
```


> **Note**: The default value for `ipipMode` is `Always`, and therefore may be omitted
> from the request. It is included above for clarity.
{: .alert .alert-info}


### Configuring CrossSubnet IP-in-IP

IP-in-IP encapsulation can also be performed selectively, only for traffic crossing
subnet boundaries.  This provides better performance in AWS multi-AZ deployments,
and in general when deploying on networks where pools of nodes with L2 connectivity
are connected via a router.

To enable this feature, using an IP-in-IP `ipipMode` of `CrossSubnet`.

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 to use IP-in-IP with mode `CrossSubnet`:


```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-cs-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: CrossSubnet
  natOutgoing: true
EOF
```
