---
title: Network Policy Resource (NetworkPolicy)
no_canonical: true
---

A network policy resource (`NetworkPolicy`) represents an ordered set of rules which are applied
to a collection of endpoints that match a [label selector](#selector).

NetworkPolicy is a namespaced resource. NetworkPolicy in a specific namespace
only applies to [WorkloadEndpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint)
in that namespace. Two resources are in the same namespace if the namespace
value is set the same on both.
See [GlobalNetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy) for non-namespaced Network Policy.

NetworkPolicy resources can be used to define network connectivity rules between groups of Calico endpoints and host endpoints, and
take precedence over [Profile resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile) if any are defined.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `networkpolicy`, `networkpolicies`, `policy`, `np`, `policies`, `pol`, `pols`.

### Sample YAML

This sample policy allows TCP traffic from `frontend` endpoints to port 6379 on
`database` endpoints.

```yaml
apiVersion: projectcalico.org/v2
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  namespace: production
spec:
  selector: role == 'database'
  types:
  - ingress
  - egress
  ingress:
  - action: allow
    protocol: tcp
    source:
      selector: role == 'frontend'
    destination:
      ports:
      - 6379
  egress:
  - action: allow
```

### Definition

#### Metadata

| Field | Description  | Accepted Values   | Schema | Default |
|-------|--------------|-------------------|--------|---------|
| name | The name of the network policy. Required. |     Alphanumeric string with optional `.`, `_`, `-`, or `/`    | string |         |
| namespace | Namespace provides an additional qualification to a resource name. | | map | "default" |


#### Spec

{% include {{page.version}}/policyspec.md %}

#### Rule

{% include {{page.version}}/rule.md %}

#### ICMP

{% include {{page.version}}/icmp.md %}

#### EntityRule

{% include {{page.version}}/entityrule.md %}

#### Selector

{% include {{page.version}}/selectors.md %}

#### Ports

{% include {{page.version}}/ports.md %}


### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | No     | Yes      | NetworkPolicy is determined from Kubernetes NetworkPolicy resources.
