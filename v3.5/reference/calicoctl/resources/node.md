---
title: Node Resource (Node)
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/calicoctl/resources/node'
---

A node resource (`Node`) represents a node running {{site.prodname}}.  When adding a host
to a {{site.prodname}} cluster, a Node resource needs to be created which contains the
configuration for the `{{site.nodecontainer}}` instance running on the host.

When starting a `{{site.nodecontainer}}` instance, the name supplied to the instance should
match the name configured in the Node resource.

By default, starting a `{{site.nodecontainer}}` instance will automatically create a node resource
using the `hostname` of the compute host.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that
specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `node`, `nodes`, `no`, `nos`.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: Node
metadata:
  name: node-hostname
spec:
  bgp:
    asNumber: 64512
    ipv4Address: 10.244.0.1/24
    ipv6Address: 2001:db8:85a3::8a2e:370:7334/120
    ipv4IPIPTunnelAddr: 192.168.0.1
```

### Definition

#### Metadata

| Field  | Description                      | Accepted Values   | Schema |
|--------|----------------------------------|-------------------|--------|
| name   | The name of this node. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field  | Description                 | Accepted Values   | Schema | Default    |
|--------|-----------------------------|-------------------|--------|------------|
| bgp    | BGP configuration for this node.  Omit if using {{site.prodname}} for policy only. | | [BGP](#bgp) |
| orchRefs | Correlates this node to a node in another orchestrator. | | list of [OrchRefs](#OrchRef) |

#### OrchRef

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| nodeName    | Name of this node according to the orchestrator. | | string |
| orchestrator | Name of the orchestrator. | k8s | string |

#### BGP

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| asNumber    | The AS Number of your `{{site.nodecontainer}}`. | Optional. If omitted the global value is used (see [example modifying Global BGP settings](/{{page.version}}/usage/configuration/bgp#example) for details about modifying the `asNumber` setting). | integer |
| ipv4Address | The IPv4 address and subnet exported as the next-hop for the {{site.prodname}} endpoints on the host | The IPv4 address must be specified if BGP is enabled. | string |
| ipv6Address | The IPv6 address and subnet exported as the next-hop for the {{site.prodname}} endpoints on the host | Optional | string |
| ipv4IPIPTunnelAddr | IPv4 address of the IP-in-IP tunnel | Optional IPv4 address | string |
| routeReflectorClusterID | Enables this node as a route reflector within the given cluster | Optional IPv4 address | string |

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | Yes    | Yes      | `{{site.nodecontainer}}` data is directly tied to the Kubernetes nodes.
