| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| tag                   | Deprecated: Match on tag. |  | string | |
| notTag                | Deprecated: Negative match on tag. |  | string | |
| nets                  | Match packets with IP in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| notNets               | Negative match on CIDRs. Match packets with IP not in any of the listed CIDRs. | List of valid IPv4 or IPv6 CIDRs  | list of cidrs |
| selector    | Positive match on selected endpoints. | Valid selector | [selector](#selector) | |
| notSelector | Negative match on selected endpoints. | Valid selector | [selector](#selector) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports | | list of [ports](#ports) | |