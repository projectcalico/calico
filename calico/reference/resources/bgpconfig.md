---
title: BGP configuration
description: API for this Calico resource.
canonical_url: '/reference/resources/bgpconfig'
---

A BGP configuration resource (`BGPConfiguration`) represents BGP specific configuration options for the cluster or a
specific node.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  logSeverityScreen: Info
  nodeToNodeMeshEnabled: true
  asNumber: 63400
  serviceClusterIPs:
  - cidr: 10.96.0.0/12
  serviceExternalIPs:
  - cidr: 104.244.42.129/32
  - cidr: 172.217.3.0/24
  listenPort: 178
  bindMode: NodeIP
  communities:
  - name: bgp-large-community
    value: 63400:300:100
  prefixAdvertisements:
  - cidr: 172.218.4.0/26
    communities:
    - bgp-large-community
    - 63400:120
```

### BGP configuration definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

- The resource with the name `default` has a specific meaning - this contains the BGP global default configuration.
- The resources with the name `node.<nodename>` contain the node-specific overrides, and will be applied to the node `<nodename>`. When deleting a node the BGPConfiguration resource associated with the node will also be deleted. Only prefixAdvertisements, listenPort, and logSeverityScreen can be overridden this way.

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| logSeverityScreen | Global log level | Debug, Info, Warning, Error, Fatal | string | `Info` |
| nodeToNodeMeshEnabled | Full BGP node-to-node mesh. Only valid on the global `default` BGPConfiguration. | true, false  | string | true |
| asNumber | The default local AS Number that {{site.prodname}} should use when speaking with BGP peers. Only valid on the global `default` BGPConfiguration; to set a per-node override, use the `bgp` field on the [Node resource](./node). | A valid AS Number, may be specified in dotted notation. | integer/string | 64512 |
| serviceClusterIPs | The CIDR blocks for Kubernetes Service Cluster IPs to be advertised over BGP. Only valid on the global `default` BGPConfiguration: will be ignored otherwise. | A list of valid IPv4 or IPv6 CIDR blocks. | List of `cidr: <ip>/<prefix length>` values. | Empty List |
| serviceExternalIPs | The CIDR blocks for Kubernetes Service External IPs to be advertised over BGP. Kubernetes Service External IPs will only be advertised if they are within one of these blocks. Only valid on the global `default` BGPConfiguration: will be ignored otherwise. | A list of valid IPv4 or IPv6 CIDR blocks. | List of `cidr: <ip>/<prefix length>` values. | Empty List |
| serviceLoadBalancerIPs | The CIDR blocks for Kubernetes Service status.LoadBalancer IPs to be advertised over BGP. Kubernetes LoadBalancer IPs will only be advertised if they are within one of these blocks. Only valid on the global `default` BGPConfiguration: will be ignored otherwise. | A list of valid IPv4 or IPv6 CIDR blocks. | List of `cidr: <ip>/<prefix length>` values. | Empty List |
| listenPort | The port where BGP protocol should listen.| A valid port number. | integer | 179 |
| bindMode | Indicates whether to listen for BGP connections on all addresses (None) or only on the node's canonical IP address Node.Spec.BGP.IPvXAddress (NodeIP). If this field is changed when calico-node is already running, the change will not take effect until calico-node is manually restarted.| None, NodeIP. | string | None |
| communities | List of BGP community names and their values, communities are not advertised unless they are used in [prefixAdvertisements](#prefixadvertisements). || List of [communities](#communities) |
| prefixAdvertisements | List of per-prefix advertisement properties, like BGP communities.|| List of [prefixAdvertisements](#prefixadvertisements) |
| nodeMeshPassword   | BGP password for the all the peerings in a full mesh configuration. |  | [BGPPassword](bgppeer#bgppassword) | `nil` (no password) |
| nodeMeshMaxRestartTime  | Restart time that is announced by BIRD in the BGP graceful restart capability and that specifies how long the neighbor would wait for the BGP session to re-establish after a restart before deleting stale routes in full mesh configurations. Note: extra care should be taken when changing this configuration, as it may break networking in your cluster. When not specified, BIRD uses the default value of 120 seconds. | `10s`, `120s`, `2m` etc.  | [Duration string][parse-duration] | `nil` (empty config, BIRD will use the default value of `120s`) |

#### communities

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name | Name or identifier for the community. This should be used in [prefixAdvertisements](#prefixAdvertisements) to advertise the community value. | | string |
| value | Standard or large BGP community value. |For standard community, value should be in `aa:nn` format, where both `aa` and `nn` are 16 bit integers.<br/> For large community, value should be `aa:nn:mm` format, where `aa`, `nn` and `mm` are all 32 bit integers. <br/>Where `aa` is an AS Number, `nn` and `mm` are per-AS identifier. | string |

#### prefixAdvertisements

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| cidr | CIDR for which properties should be advertised. |`cidr: XXX.XXX.XXX.XXX/XX`| string |
| communities | BGP communities to be advertised. | Communities can be list of either community names already defined in [communities](#communities) or community value of format `aa:nn` or `aa:nn:mm`. <br/>For standard community, value should be in `aa:nn` format, where both `aa` and `nn` are 16 bit integers.<br/> For large community, value should be `aa:nn:mm` format, where `aa`, `nn` and `mm` are all 32 bit integers. <br/>Where `aa` is an AS Number, `nn` and `mm` are per-AS identifier. | List of string |

### Supported operations

| Datastore type        | Create    | Delete    | Delete (Global `default`)  |  Update  | Get/List | Notes
|-----------------------|------------|-----------|--------|----------|----------|------
| etcdv3                | Yes       | Yes    | No     | Yes      | Yes      |
| Kubernetes API server | Yes        | Yes   | No     | Yes      | Yes      |
