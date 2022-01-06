---
title: Host endpoint
description: API for this Calico resource.
canonical_url: '/reference/resources/hostendpoint'
---

A host endpoint resource (`HostEndpoint`) represents one or more real or virtual interfaces
attached to a host that is running {{site.prodname}}.  It enforces {{site.prodname}} policy on
the traffic that is entering or leaving the host's default network namespace through those
interfaces.

-  A host endpoint with `interfaceName: *` represents _all_ of a host's real or virtual
   interfaces.

-  A host endpoint for one specific real interface is configured by `interfaceName: <name-of-that-interface>`,
   for example `interfaceName: eth0`, or by leaving `interfaceName`
   empty and including one of the interface's IPs in `expectedIPs`.

Each host endpoint may include a set of labels and list of profiles that {{site.prodname}}
will use to apply
[policy]({{ site.baseurl }}/reference/resources/networkpolicy)
to the interface.

**Default behavior of external traffic to/from host**

If a host endpoint is created and network policy is not in place, the {{site.prodname}} default is to deny traffic to/from that endpoint (except for traffic allowed by failsafe rules).
For a named host endpoint (i.e. a host endpoint representing a specific interface), {{site.prodname}} blocks traffic only to/from the interface specified in the host endpoint. Traffic to/from other interfaces is ignored.

> **Note**: Host endpoints with `interfaceName: *` do not support [untracked policy]({{ site.baseurl }}/security/high-connection-workloads).
{: .alert .alert-info}

For a wildcard host endpoint (i.e. a host endpoint representing all of a host's interfaces), {{site.prodname}} blocks traffic to/from _all_ interfaces on the host (except for traffic allowed by failsafe rules).

However, profiles can be used in conjunction with host endpoints to modify default behavior of external traffic to/from the host in the absence of network policy.
{{site.prodname}} provides a default profile resource named `projectcalico-default-allow` that consists of allow-all ingress and egress rules.
Host endpoints with the `projectcalico-default-allow` profile attached will have "allow-all" semantics instead of "deny-all" in the absence of policy.

Note: If you have custom iptables rules, using host endpoints with allow-all rules (with no policies) will accept all traffic and therefore bypass those custom rules.

> Auto host endpoints specify the `projectcalico-default-allow` profile so they behave similarly to pod workload endpoints.
{: .alert .alert-info}

> **Important**: When rendering security rules on other hosts, {{site.prodname}} uses the
> `expectedIPs` field to resolve label selectors to IP addresses. If the `expectedIPs` field
> is omitted then security rules that use labels will fail to match this endpoint.
{: .alert .alert-danger}

**Host to local workload traffic**

Traffic from a host to its workload endpoints (e.g. Kubernetes pods) is always allowed, despite any policy in place. This ensures that `kubelet` liveness and readiness probes always work.

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

### Host endpoint definition

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

{% include content/endpointport.md %}

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | Yes           | Yes    | Yes      |
