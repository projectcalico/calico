| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| nets                  | Match packets with IP in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| notNets               | Negative match on CIDRs. Match packets with IP not in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| selector    | Positive match on selected endpoints. | Valid selector | [selector](#selector) | |
| notSelector | Negative match on selected endpoints. | Valid selector | [selector](#selector) | |
| namespaceSelector | Positive match on selected namespaces. If specified, only workload endpoints in the selected Kubernetes namespaces are matched. | Valid selector | [selector](#selector) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports | | list of [ports](#ports) | |
