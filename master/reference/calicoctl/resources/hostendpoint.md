---
title: Host Endpoint Resource (HostEndpoint)
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/calicoctl/resources/hostendpoint'
---

A host endpoint resource (`HostEndpoint`) represents one or more real or virtual interfaces
attached to a host that is running {{site.prodname}}.  It enforces {{site.prodname}} policy on
the traffic that is entering or leaving the host's default network namespace through those
interfaces.

-  A host endpoint with `interfaceName: *` represents _all_ of a host's real or virtual
   interfaces.

-  A host endpoint for one specific real interface is configured by `interfaceName:
   <name-of-that-interface>`, for example `interfaceName: eth0`, or by leaving `interfaceName`
   empty and including one of the interface's IPs in `expectedIPs`.

Each host endpoint may include a set of labels and list of profiles that {{site.prodname}}
will use to apply
[policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy)
to the interface.  If no profiles or labels are applied, {{site.prodname}} will not apply
any policy.

> **Note**: Currently, for host endpoints with `interfaceName: *`, only [pre-DNAT
> policy]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/policy/pre-dnat) is
> implemented.
{: .alert .alert-info}

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `hostendpoint`, `hostendpoints`, `hep`, `heps`.

> **Important**: When rendering security rules on other hosts, {{site.prodname}} uses the
> `expectedIPs` field to resolve label selectors to IP addresses. If the `expectedIPs` field
> is omitted then security rules that use labels will fail to match this endpoint.
{: .alert .alert-danger}

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: some.name
  labels:
    type: production
spec:
  interfaceName: eth0
  node: myhost
  expectedIPs:
  - 192.168.0.1
  - 192.168.0.2
  profiles:
  - profile1
  - profile2
  ports:
  - name: some-port
    port: 1234
    protocol: TCP
  - name: another-port
    port: 5432
    protocol: UDP
```

### HostEndpoint Definition

#### Metadata

| Field   | Description                                | Accepted Values                                     | Schema |
|---------|--------------------------------------------|-----------------------------------------------------|--------|
| name    | The name of this hostEndpoint. Required.   | Alphanumeric string with optional `.`, `_`, or `-`. | string |
| labels  | A set of labels to apply to this endpoint. |                                                     | map    |

#### Spec

| Field         | Description                                              | Accepted Values             | Schema                                 | Default |
|---------------|----------------------------------------------------------|-----------------------------|----------------------------------------|---------|
| node          | The name of the node where this HostEndpoint resides.    |                             | string                                 |
| interfaceName | Either `*` or the name of the specific interface on which to apply policy. |           | string                                 |
| expectedIPs   | The expected IP addresses associated with the interface. | Valid IPv4 or IPv6 address  | list                                   |
| profiles      | The list of profiles to apply to the endpoint.           |                             | list                                   |
| ports         | List of named ports that this workload exposes.          |                             | List of [EndpointPorts](#endpointport) |

#### EndpointPort

{% include {{page.version}}/endpointport.md %}

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |
