Entity rules are used to specify the set of entities that should be matched as the source or destination of a packet.
Packets are matched on their IP and ports, if the rule contains multiple match criteria (for example, an IP and a port) 
then all match criteria must match for the rule to match.

[Selectors](#selectors) offer a powerful way to select other resources that {{site.prodname}} is aware of as the source
or destination of traffic.  Selectors can match workload endpoints, host endpoint and (global) network sets.  

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| nets                  | Match packets with IP in any of the listed CIDRs. | List of valid IPv4 CIDRs or list of valid IPv6 CIDRs (IPv4 and IPv6 CIDRs shouldn't be mixed in one rule)  | list of cidrs |
| notNets               | Negative match on CIDRs. Match packets with IP not in any of the listed CIDRs. | List of valid IPv4 CIDRs or list of valid IPv6 CIDRs (IPv4 and IPv6 CIDRs shouldn't be mixed in one rule) | list of cidrs |
| selector    | Positive match on selected endpoints. If a `namespaceSelector` is also defined, the set of endpoints this applies to is limited to the endpoints in the selected namespaces. | Valid selector | [selector](#selectors) | |
| notSelector | Negative match on selected endpoints. If a `namespaceSelector` is also defined, the set of endpoints this applies to is limited to the endpoints in the selected namespaces. | Valid selector | [selector](#selectors) | |
| namespaceSelector | Positive match on selected namespaces. If specified, only workload endpoints in the selected Kubernetes namespaces are matched. Matches namespaces based on the labels that have been applied to the namespaces. Defines the scope that selectors will apply to, if not defined then selectors apply to the NetworkPolicy's namespace. Match a specific namespace by name using the `projectcalico.org/name` label. Select the non-namespaced resources like GlobalNetworkSet(s), host endpoints to which this policy applies by using `global()` selector. | Valid selector | [selector](#selectors) | |
| ports | Positive match on the specified ports | | list of [ports](#ports) | |
| notPorts | Negative match on the specified ports | | list of [ports](#ports) | |
| serviceAccounts | Match endpoints running under service accounts. If a `namespaceSelector` is also defined, the set of service accounts this applies to is limited to the service accounts in the selected namespaces. | | [ServiceAccountMatch](#serviceaccountmatch) | |

When using selectors in network policy, remember that selectors only match (known) resources, but _rules_ match
packets. A rule with a selector `all()` won't match "all packets", it will match "packets from all known 
endpoints and network sets".  To match all packets, simply leave out the selector(s) in your rule.   

> **Important**: `notSelector` is somewhat subtle because the `not` in `notSelector` is negating the packet match 
> rather than the selector:
> 
> * `selector: !has(foo)` will match packets from/to endpoints and network sets that do not have the label "foo".
> * `notSelector: has(foo)` will match packets from/to **anywhere** (including outside the cluster), **except** traffic from/to endpoints and network sets that have the label "foo".
{: .alert .alert-danger}
