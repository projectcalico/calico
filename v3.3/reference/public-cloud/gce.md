---
title: Deploying Calico on GCE
canonical_url: https://docs.projectcalico.org/v3.3/reference/public-cloud/gce
---

To deploy {{site.prodname}} in [Google Compute Engine][GCE], you must ensure 
that traffic between containers on different hosts is not dropped by the GCE 
fabric. There are a few different options for doing this depending on your 
deployment.

## IP-in-IP encapsulation

Container traffic routing can be enabled by setting [IP-in-IP encapsulation][IPIP]
and NAT outgoing on the configured {{site.prodname}} IP pools.

See the [IP pool configuration reference][IPPool]
for information on how to configure {{site.prodname}} IP pools.

## GCE cloud routes

Traffic routing in GCE can be achieved by utilizing GCE cloud routes and
running {{site.prodname}} in policy-only mode.  Kubernetes GCE cloud provider integration
simplifies route configuration by enabling Kubernetes to handle creating
routes.

## Enabling Workload-to-WAN Traffic

To allow {{site.prodname}} networked containers to reach resources outside of GCE,
you must configure outgoing NAT on your [{{site.prodname}} IP pool][IPPool].

GCE will perform outbound NAT on any traffic which has the source address of a virtual
machine instance.  By enabling outgoing NAT on your {{site.prodname}} IP pool, {{site.prodname}} will
NAT any outbound traffic from the containers hosted on the virtual machine instances.

[IPIP]: {{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip
[IPPool]: {{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool
[GCE]: https://cloud.google.com/compute/
