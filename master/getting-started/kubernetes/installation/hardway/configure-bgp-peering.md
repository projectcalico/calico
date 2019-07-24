---
title: Configure BGP peering
canonical_url: 'https://docs.projectcalico.org/v3.8/getting-started/kubernetes/installation/hardway/configure-bgp-peering'
---

We have configured {{site.prodname}} to distribute routing information over the
Border Gateway Protocol (BGP). This scalable protocol powers routing on the global
public Internet.

On one of the nodes in your cluster where you have `calicoctl` installed, check the status.

```
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

Notice there are 4 BGP sessions, one to each other node in the cluster. In a small cluster, this
works well and is highly resilient. However, the total number of BGP sessions scales as the square
of the number of nodes, and in a large cluster this creates a lot of overhead.

In this lab we will configure a fixed number of _route reflectors_. Route reflectors annouce their
own routes and the routes they receive from other peers. This means nodes only need to peer with the
route reflectors to get all the routes in the cluster. This peering arrangement means that the number
if BGP sessions scales linearly with the number of nodes.

## Choose and label nodes

We will establish 3 route reflectors, which means we avoid a single point of failure even if we take down
a route reflector node for maintenance. In a 5 node cluster that means that only one BGP session is not
needed, since the 2 non-reflector nodes don't need to peer with one another, but it will save lots of overhead
in a large cluster.

Choose 3 nodes and perform the following for each of them.

Save the node YAML.

```
calicoctl get node <node name> -o yaml --export > node.yaml
```

Edit the YAML to add

```
metadata:
  labels:
    calico-route-reflector: ""
spec:
  bgp:
    routeReflectorClusterID: 224.0.0.1
```

Reapply the YAML

```
calicoctl apply -f node.yaml
```

## Configure peering

Configure all non-reflector nodes to peer with all route reflectors

```
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

```
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

```
calicoctl create -f - << EOF
 apiVersion: projectcalico.org/v3
 kind: BGPConfiguration
 metadata:
   name: default
 spec:
   nodeToNodeMeshEnabled: false
   asNumber: 64512
EOF
```

On a non-reflector node, you should now see only 3 peerings.

```
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

## Next

[Test Networking](./test-networking)