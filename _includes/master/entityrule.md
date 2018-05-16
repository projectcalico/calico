| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| nets                  | Match packets with IP in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| notNets               | Negative match on CIDRs. Match packets with IP not in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| selector    | Positive match on selected endpoints. If a `namespaceSelector` is also defined, the set of endpoints this applies to is limited to the endpoints in the selected namespaces. | Valid selector | [selector](#selector) | |
| notSelector | Negative match on selected endpoints. If a `namespaceSelector` is also defined, the set of endpoints this applies to is limited to the endpoints in the selected namespaces. | Valid selector | [selector](#selector) | |
| namespaceSelector | Positive match on selected namespaces. If specified, only workload endpoints in the selected Kubernetes namespaces are matched. Matches namespaces based on the labels that have been applied to the namespaces. Defines the context that selectors will apply to, if not defined then selectors apply to the NetworkPolicy's namespace. | Valid selector | [selector](#selector) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports | | list of [ports](#ports) | |
| serviceAccounts | Match endpoints running under service accounts. If a `namespaceSelector` is also defined, the set of service accounts this applies to is limited to the service accounts in the selected namespaces. Application layer policy must be enabled to use this field. | | [ServiceAccountMatch](#serviceaccountmatch) | |

