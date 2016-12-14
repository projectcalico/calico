---
title: GCE
---

## Requirements

To deploy Calico in GCE, you must ensure that the proper firewall rules
have been made and that traffic between containers on different hosts is not
dropped by the GCE fabric. There are a few different options for doing this depending
on your deployment.

#### Configure GCE Firewall Rules

Calico requires the following firewall rules to function in GCE.

| Description      | Protocol | Port Range |
|:-----------------|:---------|:-----------|
| BGP              | TCP      | 179        |
| \*IPIP           | 4        | all        |

>\*IPIP: This rule is required only when using Calico with IPIP encapsulation.
Keep reading for information on when IPIP is required in GCE.

#### Routing Traffic

To use Calico in GCE you must enable ipip encapsulation and outgoing NAT
on your Calico IP pools. This comibination allows Calico to route container traffic without
it being dropped by the GCE fabric.

See the [IP pool configuration reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
for information on how to configure Calico IP pools.

#### Enabling Workload-to-WAN Traffic

To allow Calico networked containers to reach resources outside of GCE,
you must configure outgoing NAT on your [Calico IP pool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).

GCE will perform outbound NAT on any traffic which has the source address of an EC2 virtual
machine instance.  By enabling outgoing NAT on your Calico IP pool, Calico will
NAT any outbound traffic from the containers hosted on the EC2 virtual machine instances.
