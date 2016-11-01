---
title: Policy resource (policy)
---
# Policy Resource
Policy objects can be thought of as being applied to a set of endpoints (rather than being a property of the endpoint) to give more flexible policy arrangements that can override or augment any ACLs directly associated with an endpoint through a profile.

Each policy has a label/tag based selector predicate, such as `type == webserver && role == frontend`, that selects which endpoints it should apply to, and an order number that specifies the policy’s priority. For each endpoint, Calico applies the security policies that apply to it, in priority order, and then that endpoint’s security profiles.

### Sample YAML
```
apiVersion: v1
kind: policy
metadata:
  name: policy1
spec:
  order: 100
  selector: type=='database'
  ingress:
  - action: deny
    protocol: tcp
    icmp:
      - type: 10
      - code: 6
    notProtocol": ipv6
    notICMP:
      - type: 19
      - code: 255
    source:
      tag: footag
      net: 10.0.0.0/16
      selector: type=='application'
      ports: [1234,"10:20"]
      notTag: bartag
      notNet: 10.1.0.0/16
      notSelector: type=='database'
      notPorts: [1050]
    destination:
      tag: alphatag
      net: 10.2.0.0/16
      selector: type=='application'
      ports: ["100:200"]
      notTag: type=='bananas'
      notNet: 10.3.0.0/16
      notSelector: type=='apples'
      notPorts: ["1050:110"]
  egress:
  - action: allow
    source:
      selector: type=='application'
```
> Note: The above YAML spec defines almost all of possible fields for a policy specifications, with one exception - the "egress" section has been simplified for readability, despite the fact that it supports all fields that "ingress" does.

#### Metadata

| name | description  | requirements                  | schema |
|------|--------------|-------------------------------|--------|
| name | The name of the policy. | | string |


#### PolicySpec

| name     | description                                                          | requirements | schema |
|----------|----------------------------------------------------------------------|--------------|--------|
| order    | The order number which indicates the order that this policy is used. | | integer |
| ingress  | The ingress rules belonging to this policy.                          | | List of [RuleSpecs](#rulespec) |
| egress   | The egress rules belonging to this policy.                           | | List of [RuleSpecs](#rulespec)  |
| selector | Selector expression.                                                 | | string |

#### RuleSpec

| name        | description                                | requirements | schema |
|-------------|--------------------------------------------|----------------|--------|
| action      | Action to perform when matching this rule.  Can be one of: `allow`, `deny`, `log` |  | string |
| protocol    | Positive protocol match.  | Can be one of: `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `udplite`, or an integer 1-255. | string |
| icmp        | ICMP match criteria.     | | [ICMPSpec](#icmpspec) |
| notProtocol | Negative protocol match. | Can be one of: `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `udplite`, or an integer 1-255. | string |
| notICMP     | Negative match on ICMP. | | [ICMPSpec](#icmpspec) |
| source      | Source match parameters. |  | [EntityRule](#entityrule) |
| destination | Destination match parameters. |  | [EntityRule](#entityrule) |

#### ICMPSpec

| name | description                  | requirements         | schema  |
|------|------------------------------|----------------------|---------|
| type | Positive match on ICMP type. | Can be integer 1-255 | integer |
| code | Positive match on ICMP code. | Can be integer 1-255 | integer |

#### EntityRule

| name        | description                                | requirements                  | schema |
|-------------|--------------------------------------------|----------------|--------|
| tag      | Match expression on tags.                   |  | string |
| net    | Match on CIDR. |  | string representation of cidr |
| selector    | Selector expression. | | string |
| ports | Restricts the rule to only apply to traffic that has a port that matches one of these ranges/values. | A list of integers and/or strings, where strings can represent a range of ports by joining the range by a colon, e.g. `'1000:2000'` | list of strings and/or integers. |
| notTag | Negative match on tag. |  | string |
| notNet | Negative match on CIDR. | | string representation of cidr |
| notSelector | Negative match on selector expression. | | string |
| notPorts      | Negative match on ports. | A list of integers and/or strings, where strings can represent a range of ports by joining the range by a colon, e.g. `'1000:2000'` | list of strings and/or integers. |
