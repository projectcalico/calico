---
title: Advertising Kubernetes services over BGP
canonical_url: 'https://docs.projectcalico.org/master/usage/service-advertisement'
---

## About advertising Kubernetes services over BGP

{{site.prodname}} supports advertising Kubernetes service cluster IPs over BGP, just as it advertises pod IPs.
This means that, if your {{site.prodname}} deployment is configured to peer with BGP routers
outside the cluster, those routers - plus any further upstream places that those routers propagate to - will be able
to send traffic to a Kubernetes service cluster IP, and that traffic will be routed to one of the
available endpoints for that service.

You may want to enable this feature if you would like Kubernetes services to be accessible outside of the
cluster without the need for a dedicated load balancer.

## Prerequisites

**BGP peers**

You must have established BGP connections to one or more routers outside of your Kubernetes cluster.
See [configuring BGP peers][bgp-peers] for more information.

For ECMP load balancing to services, the upstream routers must be configured to use BGP multipath.

## Enabling service cluster IP advertisement

To enable this feature, first determine the cluster IP range in use for your cluster. This value is passed to the Kubernetes API server
using the `--service-cluster-ip-range` option, and defaults to `10.0.0.0/24`. See the [API server reference guide][apiserver] for more information.

Then, set the [`CALICO_ADVERTISE_CLUSTER_IPS` environment variable][reference] in the {{site.noderunning}} daemon set
equal to the service cluster IP range for the cluster.

The following command will enable service cluster IP advertisement on a running cluster, assuming the default cluster IP range
of `10.0.0.0/24`.

```bash
kubectl patch ds -n kube-system calico-node --patch \
    '{"spec": {"template": {"spec": {"containers": [{"name": "calico-node", "env": [{"name": "CALICO_ADVERTISE_CLUSTER_IPS", "value": "10.0.0.0/24"}]}]}}}}’
```

## Behavior

Calico implements [external traffic policy][external-traffic-policy] for Kubernetes services
using normal BGP route processing and ECMP routing.

-  traffic to the cluster IP for a service with `externalTrafficPolicy: Local` will be load-balanced across the
   nodes with endpoints for that service

-  traffic to the cluster IP for a service with `externalTrafficPolicy: Cluster` will be load-balanced across all
   the nodes in the cluster.

In order to implement this behavior, Calico does the following.

-  the service cluster IP CIDR (for example, 10.96.0.0/12) is advertised from
   every node in the cluster

-  for each active service with `externalTrafficPolicy: Local`, the
   cluster IP for that service is advertised as a /32 route from the
   nodes that have endpoints for that service.

[external-traffic-policy]: https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip
[apiserver]: https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
[reference]: {{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/config-options#configuring-service-advertisement
[bgp-peers]: {{site.baseurl}}/{{page.version}}/usage/configuration/bgp
