> ![warning](../../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../../README.md) main page.

# BGP Peer resources

## YAML format

Type
Brief description
profile
Profile objects can be thought of as describing the properties of an endpoint (virtual interface, or bare metal interface).  Each endpoint can reference zero or more profiles.  A profile encapsulates a specific set of tags, labels and ACL rules that are directly applied to the endpoint.  Depending on the use case, profiles may be sufficient to express all policy.
policy
Policy objects can be thought of as being applied to a set of endpoints (rather than being a property of the endpoint) to give more flexible policy arrangements.
Each policy has a label/tag based selector predicate, such as “type == ‘webserver’ && role == ‘frontend’”, that selects which endpoints it should apply to, and an ordering number that specifies the policy’s priority. For each endpoint, Calico applies the security policies that apply to it, in priority order, and then that endpoint’s security profiles.
A host endpoints refer to the “bare-metal” interfaces attached to the host that is running Calico’s agent, Felix.  Each endpoint may specify a set of labels and list of profiles that Calico will use to apply policy to the interface.  If no profiles or labels are applied, Calico, by default, will not apply any policy.



[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/resources/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
