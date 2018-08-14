---
title: Global Network Policy Resource (GlobalNetworkPolicy)
canonical_url: https://docs.projectcalico.org/v3.2/reference/calicoctl/resources/globalnetworkpolicy
---

A global network policy resource (`GlobalNetworkPolicy`) represents an ordered set of rules which are applied
to a collection of endpoints that match a [label selector](#selector).

`GlobalNetworkPolicy` is not a namespaced resource. `GlobalNetworkPolicy` applies to [workload endpoint resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint) in all namespaces, and to [host endpoint resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint).
Select a namespace in a `GlobalNetworkPolicy` in the standard selector by using
`projectcalico.org/namespace` as the label name and a namespace name as the
value to compare against, e.g., `projectcalico.org/namespace == "default"`.
See [network policy resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy) for namespaced network policy.

`GlobalNetworkPolicy` resources can be used to define network connectivity rules between groups of {{site.prodname}} endpoints and host endpoints, and
take precedence over [profile resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile) if any are defined.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `globalnetworkpolicy`, `globalnetworkpolicies`, `gnp`, `gnps`.

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
| name | The name of the network policy. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |         |

#### Spec

| Field          | Description                                                                                                                                           | Accepted Values | Schema                | Default |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|-----------------------|---------|
| order          | Controls the order of precedence. {{site.prodname}} applies the policy with the lowest value first.                                                              |                 | float                 |         |
| selector       | Selects the endpoints to which this policy applies.                                                                                                   |                 | [selector](#selector) | all()   |
| types          | Applies the policy based on the direction of the traffic. To apply the policy to inbound traffic, set to `ingress`. To apply the policy to outbound traffic, set to `egress`. To apply the policy to both, set to `ingress, egress`. | `ingress`, `egress` | List of strings | Depends on presence of ingress/egress rules\* |
| ingress        | Ordered list of ingress rules applied by policy.                                                                                                      |                 | List of [Rule](#rule) |         |
| egress         | Ordered list of egress rules applied by this policy.                                                                                                  |                 | List of [Rule](#rule) |         |
| doNotTrack\*\* | Indicates to apply the rules in this policy before any data plane connection tracking, and that packets allowed by these rules should not be tracked. | true, false     | boolean               | false   |
| preDNAT\*\*    | Indicates to apply the rules in this policy before any DNAT.                                                                                          | true, false     | boolean               | false   |
| applyOnForward\*\*  | Indicates to apply the rules in this policy on forwarded traffic as well as to locally terminated traffic.                                                                                          | true, false     | boolean               | false   |

\* If `types` has no value, {{site.prodname}} defaults as follows.

>| Ingress Rules Present | Egress Rules Present | `Types` value       |
 |-----------------------|----------------------|---------------------|
 | No                    | No                   | `ingress`           |
 | Yes                   | No                   | `ingress`           |
 | No                    | Yes                  | `egress`            |
 | Yes                   | Yes                  | `ingress, egress`   |

\*\* The `doNotTrack` and `preDNAT` and `applyOnForward` fields are meaningful 
only when applying policy to a [host endpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint).

Only one of `doNotTrack` and `preDNAT` may be set to `true` (in a given policy). If they are both `false`, or when applying the policy to a
[workload endpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint),
the policy is enforced after connection tracking and any DNAT.

`applyOnForward` must be set to `true` if either `doNotTrack` or `preDNAT` is 
`true` because for a given policy, any untracked rules or rules before DNAT will
 in practice apply to forwarded traffic.

See [Using {{site.prodname}} to Secure Host Interfaces]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal)
for how `doNotTrack` and `preDNAT` and `applyOnForward` can be useful for host endpoints.

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
| Kubernetes API datastore | No            | No     | Yes      |
