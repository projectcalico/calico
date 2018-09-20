---
title: Route Reflectors
canonical_url: 'https://docs.projectcalico.org/v3.2/usage/routereflector/routereflector'
---

BGP route reflectors are useful in large scale deployments, to reduce the number of BGP
connections that are needed for correct and complete route propagation.  {{site.prodname}}
includes optional route reflector function in the {{site.nodecontainer}} image, which is
enabled by provisioning the `spec.bgp.routeReflectorClusterID` field of the relevant [Node
resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node).

Some of the existing {{site.prodname}} nodes in a cluster can be [enabled to behave as route
reflectors]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp#configuring-in-cluster-route-reflectors)
(simultaneously with their function as workload hosts).

To run a standalone route reflector outside the cluster, you can also use the
{{site.nodecontainer}} image.  Use [calicoctl node
run]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run) to run a
{{site.nodecontainer}} container, then modify the relevant Node resource similarly as in the
in-cluster case.

> **Note**: The only difference between the 'in-cluster' and 'standalone' cases is that, in
> the 'standalone' case, the orchestrator is somehow instructed not to schedule any workloads
> onto the standalone route reflector nodes.
{: .alert .alert-info}

Of course there are many other ways to set up and run a non-{{site.prodname}} route reflector
outside the cluster.  You then need to [configure some or all of the {{site.prodname}} nodes
to peer with that route reflector]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp).

In addition the non-{{site.prodname}} route reflector may need configuration to accept
peerings from the {{site.prodname}} nodes, but in general that is outside the scope of this
documentation.  For example, if you installed [BIRD](https://bird.network.cz/) to be your
route reflector, you would need to configure BGP peerings like the following for each
{{site.prodname}} node that you expect to connect to it.

    protocol bgp <node_shortname> {
      description "<node_ip>";
      local as <as_number>;
      neighbor <node_ip> as <as_number>;
      multihop;
      rr client;
      graceful restart;
      import all;
      export all;
    }

> **Note**: Previous {{site.prodname}} releases offered the calico/routereflector image for
> the standalone route reflector use case.  However calico/routereflector since Calico v3.0
> has not supported route reflector clustering, and is now no longer offered at all.
> {{site.nodecontainer}} fully supports route reflector clustering.
{: .alert .alert-info}
