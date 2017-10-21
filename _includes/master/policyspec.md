| Field          | Description                                                                                                                                           | Accepted Values | Schema                | Default |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|-----------------------|---------|
| order          | Controls the order of precedence. Calico applies the policy with the lowest value first.                                                              |                 | float                 |         |
| selector       | Selects the endpoints to which this policy applies.                                                                                                   |                 | [selector](#selector) | all()   |
| types          | Applies the policy based on the direction of the traffic. To apply the policy to inbound traffic, set to `ingress`. To apply the policy to outbound traffic, set to `egress`. To apply the policy to both, set to `ingress, egress`. | `ingress`, `egress` | List of strings | Depends on presence of ingress/egress rules\* |
| ingress        | Ordered list of ingress rules applied by policy.                                                                                                      |                 | List of [Rule](#rule) |         |
| egress         | Ordered list of egress rules applied by this policy.                                                                                                  |                 | List of [Rule](#rule) |         |
| doNotTrack\*\* | Indicates to apply the rules in this policy before any data plane connection tracking, and that packets allowed by these rules should not be tracked. | true, false     | boolean               | false   |
| preDNAT\*\*    | Indicates to apply the rules in this policy before any DNAT.                                                                                          | true, false     | boolean               | false   |
| applyOnForward    | Indicates to apply the rules in this policy on forwarded traffic as well as to locally terminated traffic.                                                                                          | true, false     | boolean               | false   |

\* If `types` has no value, Calico defaults as follows.

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

See [Using Calico to Secure Host Interfaces]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal)
for how `doNotTrack` and `preDNAT` and `applyOnForward` can be useful for host endpoints.