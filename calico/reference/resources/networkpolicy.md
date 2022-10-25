---
title: Network policy
description: API for this Calico resource.
canonical_url: '/reference/resources/networkpolicy'
---

A network policy resource (`NetworkPolicy`) represents an ordered set of rules which are applied
to a collection of endpoints that match a [label selector](#selectors).

`NetworkPolicy` is a namespaced resource. `NetworkPolicy` in a specific namespace
only applies to [workload endpoint resources]({{ site.baseurl }}/reference/resources/workloadendpoint)
in that namespace. Two resources are in the same namespace if the `namespace`
value is set the same on both.
See [global network policy resource]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) for non-namespaced network policy.

`NetworkPolicy` resources can be used to define network connectivity rules between groups of {{site.prodname}} endpoints and host endpoints, and
take precedence over [profile resources]({{ site.baseurl }}/reference/resources/profile) if any are defined.

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
    metadata:
      annotations:
        from: frontend
        to: database
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

| Field     | Description                                                        | Accepted Values                                     | Schema | Default   |
|-----------|--------------------------------------------------------------------|-----------------------------------------------------|--------|-----------|
| name      | The name of the network policy. Required.                          | Alphanumeric string with optional `.`, `_`, or `-`. | string |           |
| namespace | Namespace provides an additional qualification to a resource name. |                                                     | string | "default" |

#### Spec

| Field    | Description                                                                                         | Accepted Values | Schema                | Default |
|----------|-----------------------------------------------------------------------------------------------------|-----------------|-----------------------|---------|
| order    | Controls the order of precedence. {{site.prodname}} applies the policy with the lowest value first. |                 | float                 |         |
| selector | Selects the endpoints to which this policy applies.                                                 |                 | [selector](#selectors) | all()   |
| types    | Applies the policy based on the direction of the traffic. To apply the policy to inbound traffic, set to `Ingress`. To apply the policy to outbound traffic, set to `Egress`. To apply the policy to both, set to `Ingress, Egress`. | `Ingress`, `Egress` | List of strings | Depends on presence of ingress/egress rules\* |
| ingress  | Ordered list of ingress rules applied by policy.                                                    |                 | List of [Rule](#rule) |         |
| egress   | Ordered list of egress rules applied by this policy.                                                |                 | List of [Rule](#rule) |         |
| serviceAccountSelector | Selects the service account(s) to which this policy applies. Select a specific service account by name using the `projectcalico.org/name` label.  |                 | [selector](#selectors) | all()   |

\* If `types` has no value, {{site.prodname}} defaults as follows.

>| Ingress Rules Present | Egress Rules Present | `Types` value       |
 |-----------------------|----------------------|---------------------|
 | No                    | No                   | `Ingress`           |
 | Yes                   | No                   | `Ingress`           |
 | No                    | Yes                  | `Egress`            |
 | Yes                   | Yes                  | `Ingress, Egress`   |

#### Rule

{% include content/rule.md %}

#### ICMP

{% include content/icmp.md %}

#### EntityRule

{% include content/entityrule.md %}

#### Selectors

{% include content/selectors.md %}
{% include content/selector-scopes.md %}

#### Ports

{% include content/ports.md %}

#### ServiceAccountMatch

{% include content/serviceaccountmatch.md %}

#### ServiceMatch 

{% include content/servicematch.md %}

### Application layer policy

Application layer policy is an optional feature of {{site.prodname}} and
[must be enabled]({{site.baseurl}}/security/app-layer-policy)
in order to use the following match criteria.

> **NOTE**: Application layer policy match criteria are supported with the following restrictions.
>  * Only ingress policy is supported. Egress policy must not contain any application layer policy match clauses.
>  * Rules must have the action `Allow` if they contain application layer policy match clauses.
{: .alert .alert-info}

#### HTTPMatch

{% include content/httpmatch.md %}

### Supported operations

| Datastore type           | Create/Delete | Update | Get/List | Notes
|--------------------------|---------------|--------|----------|------
| etcdv3                   | Yes           | Yes    | Yes      |
| Kubernetes API datastore | Yes           | Yes    | Yes      |
