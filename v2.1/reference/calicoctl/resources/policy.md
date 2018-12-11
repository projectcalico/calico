---
title: Policy Resource (policy)
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/calicoctl/resources/globalnetworkpolicy'
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


#### Spec

| Field      | Description                                                                                                                                                         | Accepted Values | Schema                | Default |
|------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------+-----------------------+---------|
| order      | (Optional) Indicates priority of this policy, with lower order taking precedence.  No value indicates highest order (lowest precedence)                             |                 | float                 |         |
| selector   | Selects the endpoints to which this policy applies.                                                                                                                 |                 | [selector](#selector) | all()   |
| ingress    | Ordered list of ingress rules applied by policy.                                                                                                                    |                 | List of [Rule](#rule) |         |
| egress     | Ordered list of egress rules applied by this policy.                                                                                                                |                 | List of [Rule](#rule) |         |
| doNotTrack | Indicates that the rules in this policy should be applied before any data plane connection tracking, and that packets allowed by these rules should not be tracked. | true, false     | boolean               | false   |

The `doNotTrack` field is meaningful for [host
endpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint)
only.  It does not apply at all to [workload
endpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint);
connection tracking is always used for flows to and from those.

[Untracked policy]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal) explains more about how `doNotTrack` can be useful for host endpoints.

#### Rule

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| action      | Action to perform when matching this rule. | allow, deny, log, pass | string | |
| protocol    | Positive protocol match.  | tcp, udp, icmp, icmpv6, sctp, udplite, integer 1-255. | string | |
| notProtocol | Negative protocol match. | tcp, udp, icmp, icmpv6, sctp, udplite, integer 1-255. | string | |
| icmp        | ICMP match criteria.     | | [ICMP](#icmp) | |
| notICMP     | Negative match on ICMP. | | [ICMP](#icmp) | |
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
| tag (deprecated)      | Match on tag. |  | string | |
| notTag (deprecated)   | Negative match on tag. |  | string | |
| net    | Match on CIDR. | Valid IPv4 or IPv6 CIDR  | cidr | |
| notNet | Negative match on CIDR. | Valid IPv4 or IPv6 CIDR | cidr | |
| selector    | Positive match on selected endpoints. | Valid selector | [selector](#selector) | |
| notSelector | Negative match on selected endpoints. | Valid selector | [selector](#selector) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports | | list of [ports](#ports) | |

#### Selector

{% include {{page.version}}/selectors.md %}

#### Ports

{% include {{page.version}}/ports.md %}
