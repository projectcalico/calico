---
title: BGP Peer Resource (bgpPeer)
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/resources/bgppeer'
---

A BGP Peer resource (bgpPeer) represents a remote BGP peer with which the node(s) in a Calico 
cluster will peer.  Configuring BGP peers allows you to peer a 
Calico network with your datacenter fabric (e.g. ToR). For more 
information on cluster layouts, see Calico's documentation on 
[L3 Topologies]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric).

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `bgppeer`, `bgppeers`, `bgpp`, `bgpps`, `bp`, `bps`.

### Sample YAML

```yaml
apiVersion: v1
kind: bgpPeer
metadata:
  scope: node
  node: rack1-host1
  peerIP: 192.168.1.1
spec:
  asNumber: 63400
```

### BGP Peer Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| scope    | Determines the Calico nodes to which this peer applies. | global, node | string |
| node     | Must be specified if scope is node, and must be omitted when scope is global. | The hostname of the node to which this peer applies. | string |
| peerIP   | The IP address of this peer. | Valid IPv4 or IPv6 address.  | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| asNumber | The AS Number of this peer. | A valid AS Number, may be specified in dotted notation. | integer/string |

### Peer Scopes

BGP Peers can exist at either a global scope or a node scope.  A peer's scope 
determines which Calico nodes will attempt to establish a BGP session with that peer.

#### Global Peer

If this is a `global` scoped BGP peer, all nodes in the cluster will attempt to 
establish a BGP connection with it.

#### Node Peer

A BGP peer can also be added at the `node` scope, meaning only a single specified 
node will peer with it. BGP peer resources of this nature must specify a `node` 
to inform Calico which node this peer is targeting.

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv2                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |