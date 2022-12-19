---
title: Google Compute Engine
description: Methods to ensure that traffic between containers on different hosts is not dropped by GCE fabric.
canonical_url: '/reference/public-cloud/gce'
---

To deploy {{site.prodname}} in {% include open-new-window.html text='Google Compute Engine (GCE)' url='https://cloud.google.com/compute/' %}, you must ensure that traffic between containers on different hosts is not dropped by the GCE fabric.
There are a few different options for doing this depending on your deployment.

## IP-in-IP encapsulation

Container traffic routing can be enabled by setting [IP-in-IP encapsulation]({{site.baseurl}}/networking/vxlan-ipip) and NAT outgoing on the configured {{site.prodname}} IP pools.

See the [IP pool configuration reference]({{site.baseurl}}/reference/resources/ippool) for information on how to configure {{site.prodname}} IP pools.

## GCE cloud routes

Traffic routing in GCE can be achieved by utilizing GCE cloud routes and  running {{site.prodname}} in policy-only mode.
Kubernetes GCE cloud provider integration simplifies route configuration by enabling Kubernetes to handle creating routes.

## Enabling workload-to-WAN traffic

To allow {{site.prodname}} networked containers to reach resources outside of GCE, you must configure outgoing NAT on your [{{site.prodname}} IP pool]({{site.baseurl}}/reference/resources/ippool).

GCE will perform outbound NAT on any traffic which has the source address of a virtual machine instance.
By enabling outgoing NAT on your {{site.prodname}} IP pool, {{site.prodname}} will NAT any outbound traffic from the containers hosted on the virtual machine instances.