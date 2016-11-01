---
title: Profile resource (profile)
---

Profile objects can be thought of as describing the properties of an endpoint (virtual interface, or bare metal interface).  Each endpoint can reference zero or more profiles.  A profile encapsulates a specific set of tags, labels and ACL rules that are directly applied to the endpoint.  Depending on the use case, profiles may be sufficient to express all policy.

### Sample YAML
```
apiVersion: v1
kind: profile
metadata:
  name: profile1
  labels:
  - foo:bar
spec:
  tags:
  - tag1
  - tag2s
  ingress:
  - action: deny
    protocol: tcp
    icmp:
      - type: 10
      - code: 6
    notProtocol: ipv6
    notICMP:
      - type: 19
      - code: 255
    source:
      tag: group=='production'
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
The above YAML spec defines almost all of possible fields for a profile specifications, with the following exceptions:
- "egress" supports all fields that "ingress" does.



#### Metadata

| name   | description  | requirements                  | schema |
|--------|--------------|-------------------------------|--------|
| name   | The name of the profile. | Required for `create`/`update`/`apply`/`delete`. If omitted on `get`, calicoctl enumerates over all profiles. | string |
| labels | A set of labels to apply to endpoints using this profile. |  | map of string key to string values |

#### PolicySpec

| name     | description                                                          | requirements | schema |
|----------|----------------------------------------------------------------------|--------------|--------|
| tags     | A list of tag names to apply to endpoints using this profile. Note that tags are expected to be deprecated shortly in preference to labels. Label with blank value is equivalent to tags. | | list of strings |
| ingress  | The ingress rules belonging to this policy.                          | | List of [RuleSpecs](#rulespec) |
| egress   | The egress rules belonging to this policy.                           | | List of [RuleSpecs](#rulespec)  |

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

| name        | description                                | requirements                           | schema                        |
|-------------|--------------------------------------------|----------------------------------------|-------------------------------|
| tag         | Match expression on tags.                  |                                        | string                        |
| net         | Match on CIDR.                             |                                        | string representation of cidr |
| selector    | Selector expression.                       |  | string |
| ports       | Restricts the rule to only apply to traffic that has a port that matches one of these ranges/values. | A list of integers and/or strings, where strings can represent a range of ports by joining the range by a colon, e.g. `'1000:2000'` | list of strings and/or integers. |
| notTag | Negative match on tag. |  | string |
| notNet | Negative match on CIDR. | | string representation of cidr |
| notSelector | Negative match on selector expression. | | string |
| notPorts      | Negative match on ports. | A list of integers and/or strings, where strings can represent a range of ports by joining the range by a colon, e.g. `'1000:2000'` | list of strings and/or integers. |
