> ![warning](../../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../../README.md) main page.

# BGP Peer Resource
A BGP Peer resource represents a BGP peer which node(s) in this cluster will connect to. Configuration of BGP peers is required when configuring Calico to peer with your existing datacenter infrastructure (e.g. ToR). For more information on cluster layouts, see Calico's documentation on [L3 Topologies](http://docs.projectcalico.org/en/latest/l3-interconnectFabric.html).

There are two types of BGP Peers.

#### Global Peer
If this is a `global` scoped BGP peer, all nodes in the cluster will attempt to establish a BGP connection with it.

#### Node Peer
A BGP peer can also be added at the `node` scope, meaning only a single specified node will peer with it. BGP peer resources of this nature must specify a `hostname` to inform Calico which Node this peer is targeting.


### Sample YAML
```
apiVersion: v1
kind: bgppeer
metadata:
  name: rack001-tor
  scope: node
  hostname: rack1-host1
  peerIP: 192.168.1.1
spec:
  asNumber: 63400
```

### Definitions
#### Metadata
| name     | description                                               | requirements                                                                     | schema |
|----------|-----------------------------------------------------------|----------------------------------------------------------------------------------|--------|
| name     | The name of this peer resource.                           |                                                                                  | string |
| scope    | The scope of this peer.                                   | Accepted values: `global` or `node`                                              | string |
| hostname | The hostname of the node that should peer with this peer. | Must be specified if scope is `node`, and must be omitted when scope is `global` | string |
| peerIP   | The IP address of this peer.                              | Valid IPv4 or IPv6 address.                                                      | string |

#### Spec
| name     | description                 | requirements               | schema  |
|----------|-----------------------------|----------------------------|---------|
| asNumber | The AS Number of this peer. | Must be a valid AS Number. | integer |
