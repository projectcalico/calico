---
title: Global network policy
description: API for this Calico resource.
canonical_url: '/reference/resources/globalnetworkpolicy'
---

A global network policy resource (`GlobalNetworkPolicy`) represents an ordered set of rules which are applied
to a collection of endpoints that match a [label selector](#selectors).

`GlobalNetworkPolicy` is not a namespaced resource. `GlobalNetworkPolicy` applies to [workload endpoint resources]({{ site.baseurl }}/reference/resources/workloadendpoint) in all namespaces, and to [host endpoint resources]({{ site.baseurl }}/reference/resources/hostendpoint).
Select a namespace in a `GlobalNetworkPolicy` in the standard selector by using
`projectcalico.org/namespace` as the label name and a `namespace` name as the
value to compare against, e.g., `projectcalico.org/namespace == "default"`.
See [network policy resource]({{ site.baseurl }}/reference/resources/networkpolicy) for namespaced network policy.

`GlobalNetworkPolicy` resources can be used to define network connectivity rules between groups of {{site.prodname}} endpoints and host endpoints, and
take precedence over [Profile resources]({{ site.baseurl }}/reference/resources/profile) if any are defined.

### Sample YAML

This sample policy allows TCP traffic from `frontend` endpoints to port 6379 on
`database` endpoints.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-tcp-6379
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

| Field | Description                               | Accepted Values                                     | Schema | Default |
|-------|-------------------------------------------|-----------------------------------------------------|--------|---------|
| name  | The name of the network policy. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |         |

#### Spec

| Field                  | Description                                                                                                                                                                                                                          | Accepted Values     | Schema                | Default                                       |
|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|-----------------------|-----------------------------------------------|
| order                  | Controls the order of precedence. {{site.prodname}} applies the policy with the lowest value first.                                                                                                                                  |                     | float                 |                                               |
| selector               | Selects the endpoints to which this policy applies.                                                                                                                                                                                  |                     | [selector](#selectors) | all()                                         |
| serviceAccountSelector | Selects the service account(s) to which this policy applies. Select all service accounts in the cluster with a specific name using the `projectcalico.org/name` label.                                                               |                     | [selector](#selectors) | all()                                         |
| namespaceSelector      | Selects the namespace(s) to which this policy applies. Select a specific namespace by name using the `projectcalico.org/name` label.                                                                                                 |                     | [selector](#selectors) | all()                                         |
| types                  | Applies the policy based on the direction of the traffic. To apply the policy to inbound traffic, set to `Ingress`. To apply the policy to outbound traffic, set to `Egress`. To apply the policy to both, set to `Ingress, Egress`. | `Ingress`, `Egress` | List of strings       | Depends on presence of ingress/egress rules\* |
| ingress                | Ordered list of ingress rules applied by policy.                                                                                                                                                                                     |                     | List of [Rule](#rule) |                                               |
| egress                 | Ordered list of egress rules applied by this policy.                                                                                                                                                                                 |                     | List of [Rule](#rule) |                                               |
| doNotTrack\*\*         | Indicates to apply the rules in this policy before any data plane connection tracking, and that packets allowed by these rules should not be tracked.                                                                                | true, false         | boolean               | false                                         |
| preDNAT\*\*            | Indicates to apply the rules in this policy before any DNAT.                                                                                                                                                                         | true, false         | boolean               | false                                         |
| applyOnForward\*\*     | Indicates to apply the rules in this policy on forwarded traffic as well as to locally terminated traffic.                                                                                                                           | true, false         | boolean               | false                                         |

\* If `types` has no value, {{site.prodname}} defaults as follows.

>| Ingress Rules Present | Egress Rules Present | `Types` value       |
 |-----------------------|----------------------|---------------------|
 | No                    | No                   | `Ingress`           |
 | Yes                   | No                   | `Ingress`           |
 | No                    | Yes                  | `Egress`            |
 | Yes                   | Yes                  | `Ingress, Egress`   |

\*\* The `doNotTrack` and `preDNAT` and `applyOnForward` fields are meaningful
only when applying policy to a [host endpoint]({{ site.baseurl }}/reference/resources/hostendpoint).

Only one of `doNotTrack` and `preDNAT` may be set to `true` (in a given policy). If they are both `false`, or when applying the policy to a
[workload endpoint]({{ site.baseurl }}/reference/resources/workloadendpoint),
the policy is enforced after connection tracking and any DNAT.

`applyOnForward` must be set to `true` if either `doNotTrack` or `preDNAT` is
`true` because for a given policy, any untracked rules or rules before DNAT will
 in practice apply to forwarded traffic.

See [Policy for hosts]({{ site.baseurl }}/security/hosts)
for how `doNotTrack` and `preDNAT` and `applyOnForward` can be useful for host endpoints.

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
