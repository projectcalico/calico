---
title: Configuring IP-in-IP
canonical_url: 'https://docs.projectcalico.org/v3.1/usage/configuration/ip-in-ip'
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
$ calicoctl apply -f - << EOF
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
$ calicoctl apply -f - << EOF
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

> **Note**: The `CrossSubnet` mode option requires each {{site.prodname}} node to be configured
> with the IP address and subnet of the host. However, the subnet configuration
> was only introduced in Calico v2.1. If any nodes in your deployment were originally
> created with an older version of {{site.prodname}}, or if you are unsure whether
> your deployment is configured correctly, follow the steps in
> [Upgrading from pre-v2.1](#upgrading-from-pre-v21) before enabling `CrossSubnet` IPIP.
>
{: .alert .alert-info}


#### Upgrading from pre-v2.1

If you are planning to use CrossSubnet IPIP, your entire deployment must be running with
Calico v2.1 or higher.  See [releases page]({{site.baseurl}}/{{page.version}}/releases)
for details on the component versions for each release.

Upgrade your deployment to use the latest {{site.prodname}} versions - the process for this
will be dependent on your orchestration system (if using one).

Prior to Calico v2.1, the subnet information was not detected and stored on the
node configuration.  Thus, if you have `{{site.nodecontainer}}` instances that were deployed
prior to v2.1, the node configuration may need updating to fix the host subnet.
The subnet configuration must be set correctly for each node before `CrossSubnet`
IPIP mode is enabled.

You can verify which of your nodes is correctly configured using calicoctl.

Run `calicoctl get nodes --output=wide` to check the configuration.  e.g.

```
$ calicoctl get nodes --output=wide
NAME    ASN       IPV4           IPV6
node1   (64512)   10.0.2.15/24
node2   (64512)   10.0.2.10/32
```

In this example, node1 has the correct subnet information whereas node2 needs
to be fixed.

The subnet configuration may be fixed in a few different ways depending on how
you have deployed your `{{site.nodecontainer}}` containers.  This is discussed in the
[Configuring a Node IP Address and Subnet guide]({{site.baseurl}}/{{page.version}}/usage/configuration/node).
