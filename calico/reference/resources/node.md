---
title: Node
description: API for this Calico resource.
canonical_url: '/reference/resources/node'
---

A node resource (`Node`) represents a node running {{site.prodname}}.  When adding a host
to a {{site.prodname}} cluster, a node resource needs to be created which contains the
configuration for the `{{site.nodecontainer}}` instance running on the host.

When starting a `{{site.nodecontainer}}` instance, the name supplied to the instance should
match the name configured in the Node resource.

By default, starting a `{{site.nodecontainer}}` instance will automatically create a node resource
using the `hostname` of the compute host.

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
| ipv4VXLANTunnelAddr | IPv4 address of the VXLAN tunnel. This is system configured and should not be updated manually. | | string |
| vxlanTunnelMACAddr | MAC address of the IPv4 VXLAN tunnel. This is system configured and should not be updated manually. | | string |
| ipv6VXLANTunnelAddr | IPv6 address of the VXLAN tunnel. This is system configured and should not be updated manually. | | string |
| vxlanTunnelMACAddrV6 | MAC address of the IPv6 VXLAN tunnel. This is system configured and should not be updated manually. | | string |
| orchRefs | Correlates this node to a node in another orchestrator. | | list of [OrchRefs](#OrchRef) |
| wireguard | WireGuard configuration for this node. This is applicable only if WireGuard is enabled in [Felix Configuration]({{ site.baseurl }}/reference/resources/felixconfig). | | [WireGuard](#wireguard) |

#### OrchRef

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| nodeName    | Name of this node according to the orchestrator. | | string |
| orchestrator | Name of the orchestrator. | k8s | string |

#### BGP

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| asNumber    | The AS Number of your `{{site.nodecontainer}}`. | Optional. If omitted the global value is used (see [example modifying Global BGP settings](/networking/bgp) for details about modifying the `asNumber` setting). | integer |
| ipv4Address | The IPv4 address and subnet exported as the next-hop for the {{site.prodname}} endpoints on the host | The IPv4 address must be specified if BGP is enabled. | string |
| ipv6Address | The IPv6 address and subnet exported as the next-hop for the {{site.prodname}} endpoints on the host | Optional | string |
| ipv4IPIPTunnelAddr | IPv4 address of the IP-in-IP tunnel. This is system configured and should not be updated manually. | Optional IPv4 address | string |
| routeReflectorClusterID | Enables this node as a route reflector within the given cluster | Optional IPv4 address | string |

#### WireGuard

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| interfaceIPv4Address | The IP address and subnet for the IPv4 WireGuard interface created by Felix on this node. | Optional | string |
| interfaceIPv6Address | The IP address and subnet for the IPv6 WireGuard interface created by Felix on this node. | Optional | string |

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | Yes    | Yes      | `{{site.nodecontainer}}` data is directly tied to the Kubernetes nodes.
