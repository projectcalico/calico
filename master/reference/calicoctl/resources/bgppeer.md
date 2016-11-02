---
title: BGP Peer Resource (bgpPeer)
---

A BGP Peer resource (bgpPeer) represents a BGP peer which the node(s) in a Calico 
cluster will peer with.  Configuration of BGP peers is required when configuring 
Calico network to peer with your existing datacenter fabric (e.g. ToR). For more 
information on cluster layouts, see Calico's documentation on 
[L3 Topologies]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric).

Calico has the concept of two scopes of BGP Peer resource, used to identify which 
Calico nodes are connecting to the peer represented by the resource.

#### Global Peer

If this is a `global` scoped BGP peer, all nodes in the cluster will attempt to 
establish a BGP connection with it.

#### Node Peer

A BGP peer can also be added at the `node` scope, meaning only a single specified 
node will peer with it. BGP peer resources of this nature must specify a `node` 
to inform Calico which node this peer is targeting.

### Sample YAML

```
apiVersion: v1
kind: bgppeer
metadata:
  scope: node
  node: rack1-host1
  peerIP: 192.168.1.1
spec:
  asNumber: 63400
```

### Definitions

#### Metadata

| name     | description                                               | requirements                                                                     | schema |
|----------|-----------------------------------------------------------|----------------------------------------------------------------------------------|--------|
| scope    | The scope of this peer.                                   | Accepted values: `global` or `node`                                              | string |
| node     | The hostname of the node that should peer with this peer. | Must be specified if scope is `node`, and must be omitted when scope is `global` | string |
| peerIP   | The IP address of this peer.                              | Valid IPv4 or IPv6 address.                                                      | string |

#### Spec

| name     | description                 | requirements               | schema  |
|----------|-----------------------------|----------------------------|---------|
| asNumber | The AS Number of this peer. | Must be a valid AS Number.  The YAML or JSON format may be a string and may be specified in dotted notation. | integer |
