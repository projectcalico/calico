---
title: BGP configuration
redirect_from: latest/reference/calicoctl/resources/bgpconfig
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/resources/bgpconfig'
---

A BGP configuration resource (`BGPConfiguration`) represents BGP specific configuration options for the cluster or a
specific node.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `bgpconfiguration`, `bgpconfig`, `bgpconfigurations`, `bgpconfigs`.

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
```

### BGP configuration definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

- The resource with the name `default` has a specific meaning - this contains the BGP global default configuration.
- The resources with the name `node.<nodename>` contain the node-specific overrides, and will be applied to the node `<nodename>`. When deleting a node the BGPConfiguration resource associated with the node will also be deleted.

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| logSeverityScreen | Global log level | Debug, Info, Warning, Error, Fatal | string | `Info` |
| nodeToNodeMeshEnabled | Full BGP node-to-node mesh. Only valid on the global `default` BGPConfiguration. | true, false  | string | true |
| asNumber | The default local AS Number that {{site.prodname}} should use when speaking with BGP peers. Only valid on the global `default` BGPConfiguration; to set a per-node override, use the `bgp` field on the [Node resource](./node). | A valid AS Number, may be specified in dotted notation. | integer/string | 64512 |

### Supported operations

| Datastore type        | Create    | Delete    | Delete (Global `default`)  |  Update  | Get/List | Notes
|-----------------------|------------|-----------|--------|----------|----------|------
| etcdv3                | Yes       | Yes    | No     | Yes      | Yes      |
| Kubernetes API server | Yes        | Yes   | No     | Yes      | Yes      |
