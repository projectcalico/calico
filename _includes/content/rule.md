| Field       | Description                                | Accepted Values                                                   | Schema                    | Default    |
|-------------|--------------------------------------------|-------------------------------------------------------------------|---------------------------|------------|
| metadata    | Per-rule metadata.                         |                                                                   | [RuleMetadata](#rulemetadata) |        |
| action      | Action to perform when matching this rule. | `Allow`, `Deny`, `Log`, `Pass`                                    | string                    |            |
| protocol    | Positive protocol match.                   | `TCP`, `UDP`, `ICMP`, `ICMPv6`, `SCTP`, `UDPLite`, `1`-`255`      | string \| integer         |            |
| notProtocol | Negative protocol match.                   | `TCP`, `UDP`, `ICMP`, `ICMPv6`, `SCTP`, `UDPLite`, `1`-`255`      | string \| integer         |            |
| icmp        | ICMP match criteria.                       |                                                                   | [ICMP](#icmp)             |            |
| notICMP     | Negative match on ICMP.                    |                                                                   | [ICMP](#icmp)             |            |
| ipVersion   | Positive IP version match.                 | `4`, `6`                                                          | integer                   |            |
| source      | Source match parameters.                   |                                                                   | [EntityRule](#entityrule) |            |
| destination | Destination match parameters.              |                                                                   | [EntityRule](#entityrule) |            |
| http        | Match HTTP request parameters. Application layer policy must be enabled to use this field. |                   | [HTTPMatch](#httpmatch)   |            |

An `action` of `Pass` will skip over the remaining policies and jump to the
first [profile]({{ site.baseurl }}/reference/resources/profile) assigned to the endpoint, applying the policy configured in the
profile; if there are no Profiles configured for the endpoint the default
applied action is `Deny`.

#### RuleMetadata

Metadata associated with a specific rule (rather than the policy as a whole). The contents of the metadata does not affect how a rule is interpreted or enforced; it is
simply a way to store additional information for use by operators or applications that interact with {{site.prodname}}.

| Field       | Description                         | Schema                  | Default |
|-------------|-------------------------------------|-------------------------|---------|
| annotations | Arbitrary non-identifying metadata. | map of string to string |         |

Annotations follow the
[same rules as Kubernetes for valid syntax and character set](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set).

On Linux with the iptables dataplane, rule annotations are rendered as comments in the form `-m comment --comment "<key>=<value>"` on the iptables rule(s) that correspond
to the {{site.prodname}} rule.