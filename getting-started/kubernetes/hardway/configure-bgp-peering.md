---
title: Configure BGP peering
description: Quick review of BGP peering options. 
canonical_url: '/getting-started/kubernetes/hardway/configure-bgp-peering'
---

We have configured {{site.prodname}} to distribute routing information over the
Border Gateway Protocol (BGP). This scalable protocol powers routing on the global
public Internet.

In many on-premise data centers, each server connects to a top-of-rack (ToR) router
operating at the IP layer (layer 3). In that situation, we would need to peer each node
with its corresponding ToR router, so that the ToR learns routes to the containers. That
configuration is beyond the scope of this guide.

Since we are running in an AWS VPC within a single subnet, the hosts have ethernet (layer 2)
connectivity with one another, meaning there are no routers between them. Thus, they can peer
directly with each other.

On one of the nodes in your cluster where you have `calicoctl` installed, check the status.

```bash
sudo calicoctl node status
```

Result

```
Calico process is running.

IPv4 BGP status
+---------------+-------------------+-------+----------+-------------+
| PEER ADDRESS  |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+---------------+-------------------+-------+----------+-------------+
| 172.31.40.217 | node-to-node mesh | up    | 17:38:47 | Established |
| 172.31.40.30  | node-to-node mesh | up    | 17:40:09 | Established |
| 172.31.45.29  | node-to-node mesh | up    | 17:40:20 | Established |
| 172.31.37.123 | node-to-node mesh | up    | 17:40:29 | Established |
+---------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
{: .no-select-button}

Alternatively, you can create a [`CalicoNodeStatus` resource]({{site.baseurl}}/reference/resources/caliconodestatus) to get BGP session status for the node.

Notice there are four BGP sessions, one to each other node in the cluster. In a small cluster, this
works well and is highly resilient. However, the total number of BGP sessions scales as the square
of the number of nodes, and in a large cluster this creates a lot of overhead.

In this lab we will configure a fixed number of _route reflectors_. Route reflectors announce their
own routes and the routes they receive from other peers. This means nodes only need to peer with the
route reflectors to get all the routes in the cluster. This peering arrangement means that the number
of BGP sessions scales linearly with the number of nodes.

## Choose and label nodes

We will establish three route reflectors, which means we avoid a single point of failure even if we take down
a route reflector node for maintenance. In a five node cluster that means that only one BGP session is not
needed, since the two non-reflector nodes don't need to peer with one another, but it will save lots of overhead
in a large cluster.

Choose three nodes and perform the following for each of them.

Save the node YAML.

```bash
calicoctl get node <node name> -o yaml --export > node.yaml
```

Edit the YAML to add

```yaml
metadata:
  labels:
    calico-route-reflector: ""
spec:
  bgp:
    routeReflectorClusterID: 224.0.0.1
```

Reapply the YAML

```bash
calicoctl apply -f node.yaml
```

## Configure peering

Configure all non-reflector nodes to peer with all route reflectors

```bash
calicoctl apply -f - <<EOF
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: peer-to-rrs
spec:
  nodeSelector: "!has(calico-route-reflector)"
  peerSelector: has(calico-route-reflector)
EOF
```

Configure all route reflectors to peer with each other

```bash
calicoctl apply -f - <<EOF
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: rrs-to-rrs
spec:
  nodeSelector: has(calico-route-reflector)
  peerSelector: has(calico-route-reflector)
EOF
```

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

On a non-reflector node, you should now see only three peerings.

```bash
sudo calicoctl node status
```

Result

```
Calico process is running.

IPv4 BGP status
+---------------+---------------+-------+----------+-------------+
| PEER ADDRESS  |   PEER TYPE   | STATE |  SINCE   |    INFO     |
+---------------+---------------+-------+----------+-------------+
| 172.31.37.123 | node specific | up    | 21:52:57 | Established |
| 172.31.40.217 | node specific | up    | 21:52:57 | Established |
| 172.31.42.47  | node specific | up    | 21:52:57 | Established |
+---------------+---------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
{: .no-select-button}

Alternatively, you can create a [`CalicoNodeStatus` resource]({{site.baseurl}}/reference/resources/caliconodestatus) to get BGP session status for the node.

## Next

[Test networking](./test-networking)
