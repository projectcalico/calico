---
title: Advertising Kubernetes services over BGP
canonical_url: 'https://docs.projectcalico.org/master/usage/service-advertisement'
---

{{site.prodname}} supports advertising Kubernetes service cluster IPs
over BGP, just as it advertises pod IPs.  This means that, if your
{{site.prodname}} deployment is configured to peer with BGP routers
outside the cluster, those routers - plus any further upstream places
that those routers propagate to - will be able to send traffic to a
Kubernetes service cluster IP, and that traffic will be routed to one
of the available endpoints for that service.

This feature is enabled for each {{site.prodname}} node by [setting
the `ADVERTISE_CLUSTER_IPS` environment
variable]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/config-options#configuring-service-advertisement).

When this feature is enabled:

-  the cluster IP CIDR (for example, 10.96.0.0/12) is advertised from
   every node in the cluster

-  for each active service with `externalTrafficPolicy: Local`, the
   cluster IP for that service is advertised as a /32 route from the
   nodes that have endpoints for that service.

Then, by normal BGP route processing and Linux ECMP routing,

-  traffic to the cluster IP for a service with
   `externalTrafficPolicy: Local` will be load-balanced across the
   nodes with endpoints for that service

-  traffic to the cluster IP for a service with
   `externalTrafficPolicy: Cluster` will be load-balanced across all
   the nodes in the cluster.
