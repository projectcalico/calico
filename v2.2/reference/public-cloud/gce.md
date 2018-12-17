---
title: Deploying Calico on GCE
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/public-cloud/gce'
---

To deploy Calico in [Google Compute Engine][GCE], you must ensure that the
proper firewall rules have been made and that traffic between containers on
different hosts is not dropped by the GCE fabric. There are a few different
options for doing this depending on your deployment.

#### Configure GCE Firewall Rules

Calico requires the following firewall rules to function in GCE.

| Description      | Protocol | Port Range |
|:-----------------|:---------|:-----------|
| BGP              | TCP      | 179        |
| \*IPIP           | 4        | all        |

>\*IPIP: This rule is required only when using Calico with IPIP encapsulation.
Keep reading for information on when IPIP is required in GCE.

#### Routing Traffic

One of the following options must be utilized when using Calico in
GCE to ensure container traffic is allowed by the GCE network fabric.

##### IP-in-IP encapsulation

Container traffic routing can be enabled by setting [IP-in-IP encapsulation][IPIP]
and NAT outgoing on the configured Calico IP pools.

See the [IP pool configuration reference][IPPool]
for information on how to configure Calico IP pools.

##### GCE cloud routes

Traffic routing in GCE can be achieved by utilizing GCE cloud routes and
running Calico in policy-only mode.  Kubernetes GCE cloud provider integration
simplifies route configuration by enabling Kubernetes to handle creating
routes.

#### Enabling Workload-to-WAN Traffic

To allow Calico networked containers to reach resources outside of GCE,
you must configure outgoing NAT on your [Calico IP pool][IPPool].

GCE will perform outbound NAT on any traffic which has the source address of a virtual
machine instance.  By enabling outgoing NAT on your Calico IP pool, Calico will
NAT any outbound traffic from the containers hosted on the virtual machine instances.

[IPIP]: {{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip
[IPPool]: {{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool
[GCE]: https://cloud.google.com/compute/
