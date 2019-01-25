---
title: Policy Resource (policy)
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/resources/globalnetworkpolicy'
---

A Policy resource (policy) represents an ordered set of rules which are applied
to a collection of endpoints which match a [label selector](#selector).

Policy resources can be used to define network connectivity rules between groups of Calico endpoints and host endpoints, and
take precedence over [Profile resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile) if any are defined.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `policy`, `policies`, `pol`, `pols`.

### Sample YAML

This sample policy allows TCP traffic from `frontend` endpoints to port 6379 on
`database` endpoints.

```yaml
apiVersion: v1
kind: policy
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

| Field | Description  | Accepted Values   | Schema |
|-------|--------------|-------------------|--------|
| name | The name of the policy. |         | string |
| annotations | Opaque key/value information to be used by clients. | | map |


#### Spec

| Field          | Description                                                                                                                                           | Accepted Values | Schema                | Default |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|-----------------------|---------|
| order          | Controls the order of precedence. Calico applies the policy with the lowest value first.                                                              |                 | float                 |         |
| selector       | Selects the endpoints to which this policy applies.                                                                                                   |                 | [selector](#selector) | all()   |
| types          | Applies the policy based on the direction of the traffic. To apply the policy to inbound traffic, set to `ingress`. To apply the policy to outbound traffic, set to `egress`. To apply the policy to both, set to `ingress, egress`. | `ingress`, `egress` | List of strings | Depends on presence of ingress/egress rules\* |
| ingress        | Ordered list of ingress rules applied by policy.                                                                                                      |                 | List of [Rule](#rule) |         |
| egress         | Ordered list of egress rules applied by this policy.                                                                                                  |                 | List of [Rule](#rule) |         |
| doNotTrack\*\* | Indicates to apply the rules in this policy before any data plane connection tracking, and that packets allowed by these rules should not be tracked. | true, false     | boolean               | false   |
| preDNAT\*\*    | Indicates to apply the rules in this policy before any DNAT.                                                                                          | true, false     | boolean               | false   |

\* If `types` has no value, Calico defaults as follows.

>| Ingress Rules Present | Egress Rules Present | `Types` value       |
 |-----------------------|----------------------|---------------------|
 | No                    | No                   | `ingress`           |
 | Yes                   | No                   | `ingress`           |
 | No                    | Yes                  | `egress`            |
 | Yes                   | Yes                  | `ingress, egress`   |

\*\* The `doNotTrack` and `preDNAT` fields are meaningful only when applying policy to a
[host endpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint).
Only one of them may be set to `true` (in a given policy). If they are both `false`, or when applying the policy to a
[workload endpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint),
the policy is enforced after connection tracking and any DNAT.

See [Using Calico to Secure Host Interfaces]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal)
for how `doNotTrack` and `preDNAT` can be useful for host endpoints.

#### Rule

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| action      | Action to perform when matching this rule. | allow, deny, log, pass | string | |
| protocol    | Positive protocol match.  | tcp, udp, icmp, icmpv6, sctp, udplite, integer 1-255. | string | |
| notProtocol | Negative protocol match. | tcp, udp, icmp, icmpv6, sctp, udplite, integer 1-255. | string | |
| icmp        | ICMP match criteria.     | | [ICMP](#icmp) | |
| notICMP     | Negative match on ICMP. | | [ICMP](#icmp) | |
| ipVersion   | Positive IP version match. | `4`, `6` | integer | |
| source      | Source match parameters. |  | [EntityRule](#entityrule) | |
| destination | Destination match parameters. |  | [EntityRule](#entityrule) | |

An `action` of `pass` will skip over the remaining Policies and jump to the
first Profile assigned to the endpoint, applying the policy configured in the
Profile; if there are no Profiles configured for the endpoint the default
applied action is deny.

#### ICMP

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| type | Match on ICMP type. | Can be integer 1-255 | integer |
| code | Match on ICMP code. | Can be integer 1-255 | integer |

#### EntityRule

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| tag                   | Deprecated: Match on tag. |  | string | |
| notTag                | Deprecated: Negative match on tag. |  | string | |
| nets                  | Match packets with IP in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| net                   | Deprecated (use "nets" instead): Match on CIDR. | Valid IPv4 or IPv6 CIDR  | cidr | |
| notNets               | Negative match on CIDRs. Match packets with IP not in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| notNet                | Deprecated (use "notNets" instead): Negative match on CIDR. | Valid IPv4 or IPv6 CIDR | cidr | |
| selector    | Positive match on selected endpoints. | Valid selector | [selector](#selector) | |
| notSelector | Negative match on selected endpoints. | Valid selector | [selector](#selector) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports | | list of [ports](#ports) | |

#### Selector

{% include {{page.version}}/selectors.md %}

#### Ports

{% include {{page.version}}/ports.md %}


### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv2                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | No     | Yes      | Policy is determined from Kubernetes NetworkPolicy resources.
