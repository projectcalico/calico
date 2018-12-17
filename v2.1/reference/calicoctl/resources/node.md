---
title: Node Resource (node)
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/calicoctl/resources/node'
---

An Node resource (node) represents a node running Calico.  When adding a host
to a Calico cluster, a Node resource needs to be created which contains the
configuration for the Calico Node instance running on the host.

When starting a Calico node instance, the name supplied to the instance should 
match the name configured in the Node resource.  

By default, starting a `calico/node` instance will automatically create a node resource 
using the `hostname` of the compute host.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `node`, `nodes`, `no`, `nos`.

### Sample YAML

```yaml
apiVersion: v1
kind: node
metadata:
  name: node-hostname
spec:
  bgp:
    asNumber: 64512
    ipv4Address: 10.244.0.1/24
    ipv6Address: 2001:db8:85a3::8a2e:370:7334/120
```

### Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | The name of this node.          | The value passed to the node instance on the host. | string |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| bgp      | BGP configuration for this node.  Omit if using Calico for policy only. | | [BGP](#bgp) |

#### BGP 

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| asNumber    | The AS Number of your Calico node. | Optional.  If omitted the global value is used (see [calicoctl config]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/config) for details). | integer |
| ipv4Address | The IPv4 address and subnet exported as the next-hop for the Calico endpoints on the host | The IPv4 address must be specified if BGP is enabled. | string |
| ipv6Address | The IPv6 address and subnet exported as the next-hop for the Calico endpoints on the host | Optional.  | string |
