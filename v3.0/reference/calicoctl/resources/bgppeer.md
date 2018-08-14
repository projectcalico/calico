---
title: BGP Peer Resource (BGPPeer)
canonical_url: https://docs.projectcalico.org/v3.2/reference/calicoctl/resources/bgppeer
---

A BGP peer resource (`BGPPeer`) represents a remote BGP peer with which the node(s) in a Calico 
cluster will peer.  Configuring BGP peers allows you to peer a 
Calico network with your datacenter fabric (e.g. ToR). For more 
information on cluster layouts, see Calico's documentation on 
[L3 Topologies]({{site.baseurl}}/{{page.version}}/reference/private-cloud/l3-interconnect-fabric).

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `bgppeer`, `bgppeers`, `bgpp`, `bgpps`, `bp`, `bps`.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: some.name
spec:
  node: rack1-host1
  peerIP: 192.168.1.1
  asNumber: 63400
```

### BGP Peer Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Must be specified.| Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| node     | If specified, the scope is node level, otherwise the scope is global. | The hostname of the node to which this peer applies. | string | |
| peerIP   | The IP address of this peer. | Valid IPv4 or IPv6 address.  | string | |
| asNumber | The remote AS Number of the peer. | A valid AS Number, may be specified in dotted notation. | integer/string | |

> **Tip**: the cluster-wide default local AS number used when speaking with a peer is controlled by the
> [BGPConfiguration resource](./bgpconfig).  That value can be overriden per-node by using the `bgp` field of
> the [Node resource](./node).
{: .alert .alert-success}

### Peer Scopes

BGP Peers can exist at either a global scope or a node scope. A peer's scope 
determines which Calico nodes will attempt to establish a BGP session with that peer.

#### Global Peer

To assign a BGP peer a global scope, omit the `node` field. All nodes in 
the cluster will attempt to establish BGP connections with it

#### Node Peer

A BGP peer can also be added at the node scope. When the node field is included, only the specified node
will peer with it. BGP peer resources of this nature must specify a `node` to inform Calico which node
this peer is targeting.

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |
