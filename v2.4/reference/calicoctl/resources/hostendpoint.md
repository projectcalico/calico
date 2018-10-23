---
title: Host Endpoint Resource (hostEndpoint)
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/calicoctl/resources/hostendpoint'
---

A Host Endpoint resource (hostEndpoint) represents an interface attached to a host that is running Calico.

Each host endpoint may include a set of labels and list of profiles that Calico
will use to apply
[policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy)
to the interface.  If no profiles or labels are applied, Calico will not apply
any policy.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `hostendpoint`, `hostendpoints`, `hep`, `heps`.

### Sample YAML

```yaml
apiVersion: v1
kind: hostEndpoint
metadata:
  name: eth0
  node: myhost
  labels:
    type: production
spec:
  interfaceName: eth0
  expectedIPs:
  - 192.168.0.1
  - 192.168.0.2
  profiles:
  - profile1
  - profile2
```

### HostEndpoint Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema  |
|-------------|-----------------------------|-------------------|---------|
| name        | The name of this hostEndpoint. |      | string |
| node        | The name of the node where this hostEndpoint resides. |      | string |
| labels      | A set of labels to apply to this endpoint. |      | map    |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| interfaceName | The name of the interface on which to apply policy.      |                             | string          |
| expectedIPs   | The expected IP addresses associated with the interface. | Valid IPv4 or IPv6 address  | list |
| profiles      | The list of profiles to apply to the endpoint.           |                             | list |

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv2                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | No     | No       |