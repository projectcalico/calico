---
title: Profile Resource (profile)
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/calicoctl/resources/profile'
---

A Profile resource (profile) represents a set of rules which are applied 
to the individual endpoints to which this profile has been assigned.

Each Calico endpoint or host endpoint can be assigned to zero or more profiles.

Also see the [Policy resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) 
which provides an alternate way to select what policy is applied to an endpoint.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `profile`, `profiles`, `pro`, `pros`.

### Sample YAML

The following sample profile allows all traffic from endpoints that
have the profile label set to `profile1` (i.e. endpoints that reference this profile),
except that *all* traffic from 10.0.20.0/24 is denied.

```yaml
apiVersion: v1
kind: profile
metadata:
  name: profile1
  labels:
    profile: profile1 
spec:
  ingress:
  - action: deny
    source:
      net: 10.0.20.0/24
  - action: allow
    source:
      selector: profile == 'profile1'
  egress:
  - action: allow 
```

### Definition 

#### Metadata

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| name   | The name of the profile. | | string |
| labels | A set of labels to apply to endpoints using this profile. |  | map of string key to string values |
| tags (deprecated) | A list of tag names to apply to endpoints using this profile.        | | list of strings |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| ingress  | The ingress rules belonging to this profile.                          | | List of [Rule](#rule) |
| egress   | The egress rules belonging to this profile.                           | | List of [Rule](#rule)  |

#### Rule

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| action      | Action to perform when matching this rule. | allow, deny, log | string | |
| protocol    | Positive protocol match.  | tcp, udp, icmp, icmpv6, sctp, udplite, integer 1-255. | string | |
| notProtocol | Negative protocol match. | tcp, udp, icmp, icmpv6, sctp, udplite, integer 1-255. | string | |
| icmp        | ICMP match criteria.     | | [ICMP](#icmp) | |
| notICMP     | Negative match on ICMP. | | [ICMP](#icmp) | |
| source      | Source match parameters. |  | [EntityRule](#entityrule) | |
| destination | Destination match parameters. |  | [EntityRule](#entityrule) | |

#### ICMP

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| type | Match on ICMP type. | Can be integer 1-255 | integer |
| code | Match on ICMP code. | Can be integer 1-255 | integer |

#### EntityRule

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| tag (deprecated)      | Positive match on tag. |  | string | |
| notTag (deprecated)   | Negative match on tag. |  | string | |
| net    | Match on CIDR. | Valid IPv4 or IPv6 CIDR  | cidr | |
| notNet | Negative match on CIDR. | Valid IPv4 or IPv6 CIDR | cidr | |
| selector    | Positive match on selected endpoints. | | [selector](#selector) | |
| notSelector | Negative match on selected endpoints. | | [selector](#selector) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports |  | list of [ports](#ports) | |

#### Selector

{% include {{page.version}}/selectors.md %}

#### Ports

{% include {{page.version}}/ports.md %}
