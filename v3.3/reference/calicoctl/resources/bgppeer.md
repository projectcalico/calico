---
title: BGP Peer Resource (BGPPeer)
redirect_from: latest/reference/calicoctl/resources/bgppeer
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/calicoctl/resources/bgppeer'
---

A BGP peer resource (`BGPPeer`) represents a remote BGP peer with
which the node(s) in a {{site.prodname}} cluster will peer.
Configuring BGP peers allows you to peer a {{site.prodname}} network
with your datacenter fabric (e.g. ToR). For more
information on cluster layouts, see {{site.prodname}}'s documentation on
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
| asNumber | The remote AS Number of the peer. | A valid AS Number, may be specified in dotted notation. | integer/string |
| nodeSelector | Selector for the nodes that should have this peering.  When this is set, the `node` field must be empty. | | [selector](networkpolicy#selector) |
| peerSelector | Selector for the remote nodes to peer with.  When this is set, the `peerIP` and `asNumber` fields must be empty. | | [selector](networkpolicy#selector) |

> **Tip**: the cluster-wide default local AS number used when speaking with a peer is controlled by the
> [BGPConfiguration resource](./bgpconfig).  That value can be overriden per-node by using the `bgp` field of
> the [Node resource](./node).
{: .alert .alert-success}

### Peer Scopes

BGP Peers can exist at either global or node-specific scope. A peer's scope
determines which `{{site.nodecontainer}}`s will attempt to establish a BGP session with that peer.

#### Global Peer

To assign a BGP peer a global scope, omit the `node` and `nodeSelector` fields. All nodes in
the cluster will attempt to establish BGP connections with it

#### Node-specific Peer

A BGP peer can also be node-specific. When the `node` field is included, only the specified node
will peer with it. When the `nodeSelector` field is included, the nodes with labels that match that selector
will peer with it.

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |
