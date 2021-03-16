---
title: Route reflector controller
description: Route reflector opertor scales the BGP topology inside the cluster based on given config.
---

The route reflector controller is one of the operators within [kubernetes-controllers]({{site.baseurl}}/reference/kube-controllers/configuration).

{{site.prodname}} by default doesn't manage BGP peer configuration actively. The user has to design the right topology for the specific cluster.
Route reflector controller aims to extend {{site.prodname}}'s static configurations with autoscaling based on different variables like number of active nodes or available route reflectors per zone.
The controller support multiple topologies and uses `kubernetes` custom resource for configuration, just like opther controllers.

## Topologies

Different clusters require different topologies, it depends on many parameters like size of the cluster or the number of zones. There are 3 main characteristics of a topology:

 * Number of client session
 * Number of BGP messages
 * Size of BGP messages

Each topology has different numbers, so selecting the right one needs some extra care from the user side.

### Single cluster topology

The simplest route reflector topology contains only one cluster ID. There are only one group of route reflectors and one group for clients. This topology doesn't scale well and useful only for single zone or single region clusters. The number of client connections per route reflector should go high on larger clusters than 500 nodes.

### Multi cluster topology

In this topology each Route Reflector has its own cluster ID. Clients are connecting to 3 different clusters by default and route reflectors are constituting one mesh. The size of the BGP update message should be the bottleneck near 2000 nodes, because all route reflectors advertise the full table to all other route reflectors.

## Configuration

To enable the route reflector controller, set the list of enabled controllers
in the environment for kube-controllers to `routereflector`. For example: `ENABLED_CONTROLLERS=routereflector`

Disable the node-to-node mesh

```bash
calicoctl create -f - <<EOF
 apiVersion: projectcalico.org/v3
 kind: BGPConfiguration
 metadata:
   name: default
 spec:
   nodeToNodeMeshEnabled: false
   asNumber: 64512
EOF
```

Customise topology via [resource definition]({{site.baseurl}}/reference/resources/kubecontrollersconfig).

[in-cluster-config]: https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#accessing-the-api-from-a-pod
[kubeconfig]: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
