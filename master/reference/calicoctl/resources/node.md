---
title: Node Resource (node)
---

An Node resource (node) represents a Calico node instance.  When adding a host
to a Calico node cluster, a Node resource needs to be created which contains the
starting configuration for the Calico Node instance running on the host.

When starting a Calico node instance, the name supplied to the instance should 
match then name configured in the Node resource.  By default, starting a Calico
node instance without explicitly supplying a node, will result in the instance
using the `hostname` of the compute host.

### Sample YAML

```
- apiVersion: v1
  kind: node
  metadata:
    name: node2
  spec:
    bgp:
      asNumber: 12345
      ipv4Address: 1.2.3.4
      ipv6Address: aa::ff
```

### Definitions

#### Metadata

| name     | description                     | requirements | schema |
|----------|---------------------------------|--------------|--------|
| name     | The name of this node.          | This must match the name used to start the node instance on the Calico host | string |

#### Spec

| name     | description                      | requirements | schema  |
|----------|----------------------------------|--------------|---------|
| bgp      | BGP configuration for this node  | This can be omitted if your deployment is only using Calico for policy and not for routing | [BGP Configuration](#bgp-configuration) |

#### BGP Configuration

| name        | description                 | requirements | schema  |
|-------------|-----------------------------|--------------|---------|
| asNumber    | The AS Number of your Calico node. | Optional.  If omitted the global value is used (see [calicoctl config]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/config) for details on hos to manage the global value).| integer |
| ipv4Address | The IPv4 address exported as the next-hop of the Calico endpoints on the host | Optional.  At least one of the ipv4Address or ipv6Address should be supplied. | |
| ipv6Address | The IPv6 address exported as the next-hop of the Calico endpoints on the host | Optional.  At least one of the ipv4Address or ipv6Address should be supplied. | |
