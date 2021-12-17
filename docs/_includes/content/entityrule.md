Entity rules specify the attributes of the source or destination of a packet that must match for the rule as a whole 
to match.  Packets are matched on their IPs and ports.  If the rule contains multiple match criteria (for example, an 
IP and a port) then all match criteria must match for the rule as a whole to match.

[Selectors](#selectors) offer a powerful way to select the source or destination to match based on labels.  
Selectors can match [workload endpoints]({{ site.baseurl }}/reference/resources/workloadendpoint), host endpoint and 
([namespaced]({{ site.baseurl }}/reference/resources/networkset) or
[global]({{ site.baseurl }}/reference/resources/globalnetworkset)) network sets.  

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
| services | Match the specified service(s). If specified on egress rule destinations, no other selection criteria can be set. If specified on ingress rule sources, only positive or negative matches on ports can be specified. | | [ServiceMatch](#servicematch) | |

When using selectors in network policy, remember that selectors only match (known) resources, but _rules_ match
packets. A rule with a selector `all()` won't match "all packets", it will match "packets from all in-scope 
endpoints and network sets".  To match all packets, do not include a selector in the rule at all.

> **Important**: `notSelector` is somewhat subtle because the `not` in `notSelector` negates the packet match 
> rather than the selector:
> 
> * `selector: !has(foo)` matches packets from/to endpoints and network sets that do not have the label "foo".
> * `notSelector: has(foo)` matches packets from/to **anywhere** (including outside the cluster), **except** traffic from/to endpoints and network sets that have the label "foo".
{: .alert .alert-danger}
