---
title: Global Network Policy Resource (GlobalNetworkPolicy)
---

A global network policy resource (`GlobalNetworkPolicy`) represents an ordered set of rules which are applied
to a collection of endpoints which match a [label selector](#selector).

GlobalNetworkPolicy is not a namespaced resource. GlobalNetworkPolicy applies to [WorkloadEndpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint) in all namespaces. 
See [NetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy) for namespaced Network Policy.

GlobalNetworkPolicy resources can be used to define network connectivity rules between groups of Calico endpoints and host endpoints, and
take precedence over [Profile resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile) if any are defined.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `globalnetworkpolicy`, `globalnetworkpolicies`, `gnp`, `gnps`.

### Sample YAML

This sample policy allows TCP traffic from `frontend` endpoints to port 6379 on
`database` endpoints.

```yaml
apiVersion: projectcalico.org/v2
kind: GlobalNetworkPolicy
metadata:
  name: allow-tcp-6379
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
| name | The name of the network policy. Required. | Alphanumeric string with optional `.`, `_`, `-`, or `/` | string |         |

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
| Kubernetes API server | No            | No     | Yes      | 
