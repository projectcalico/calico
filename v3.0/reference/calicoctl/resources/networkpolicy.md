---
title: Network Policy Resource (NetworkPolicy)
sitemap: false 
canonical_url: https://docs.projectcalico.org/v3.1/reference/calicoctl/resources/networkpolicy
---

A network policy resource (`NetworkPolicy`) represents an ordered set of rules which are applied
to a collection of endpoints that match a [label selector](#selector).

`NetworkPolicy` is a namespaced resource. `NetworkPolicy` in a specific namespace
only applies to [workload endpoint resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint)
in that namespace. Two resources are in the same namespace if the namespace
value is set the same on both.
See [global network policy resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy) for non-namespaced network policy.

`NetworkPolicy` resources can be used to define network connectivity rules between groups of {{site.prodname}} endpoints and host endpoints, and
take precedence over [profile resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile) if any are defined.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `networkpolicy`, `networkpolicies`, `policy`, `np`, `policies`, `pol`, `pols`.

### Sample YAML

This sample policy allows TCP traffic from `frontend` endpoints to port 6379 on
`database` endpoints.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  namespace: production
spec:
  selector: role == 'database'
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: role == 'frontend'
    destination:
      ports:
      - 6379
  egress:
  - action: Allow
```

### Definition

#### Metadata

| Field | Description  | Accepted Values   | Schema | Default |
|-------|--------------|-------------------|--------|---------|
| name | The name of the network policy. Required. |     Alphanumeric string with optional `.`, `_`, or `-`.    | string |         |
| namespace | Namespace provides an additional qualification to a resource name. | | map | "default" |


#### Spec

| Field          | Description                                                                                                                                           | Accepted Values | Schema                | Default |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|-----------------------|---------|
| order          | Controls the order of precedence. {{site.prodname}} applies the policy with the lowest value first.                                                              |                 | float                 |         |
| selector       | Selects the endpoints to which this policy applies.                                                                                                   |                 | [selector](#selector) | all()   |
| types          | Applies the policy based on the direction of the traffic. To apply the policy to inbound traffic, set to `ingress`. To apply the policy to outbound traffic, set to `egress`. To apply the policy to both, set to `ingress, egress`. | `ingress`, `egress` | List of strings | Depends on presence of ingress/egress rules\* |
| ingress        | Ordered list of ingress rules applied by policy.                                                                                                      |                 | List of [Rule](#rule) |         |
| egress         | Ordered list of egress rules applied by this policy.                                                                                                  |                 | List of [Rule](#rule) |         |

\* If `types` has no value, {{site.prodname}} defaults as follows.

>| Ingress Rules Present | Egress Rules Present | `Types` value       |
 |-----------------------|----------------------|---------------------|
 | No                    | No                   | `ingress`           |
 | Yes                   | No                   | `ingress`           |
 | No                    | Yes                  | `egress`            |
 | Yes                   | Yes                  | `ingress, egress`   |


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

| Datastore type           | Create/Delete | Update | Get/List | Notes
|--------------------------|---------------|--------|----------|------
| etcdv3                   | Yes           | Yes    | Yes      |
| Kubernetes API datastore | No            | No     | Yes      | `NetworkPolicy` is determined from Kubernetes `NetworkPolicy` resources.
