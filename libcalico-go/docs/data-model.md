# Calico etcd Data Model

This document describes the internal representation of Calico's 
datamodel in etcd.  As the Calico team are working to support pluggable
backends, this API should be considered internal and unsupported.
To manipulate Calico's datamodel, you should use the libcalico API 
bindings.

The following illustrates the directory structure calico uses in etcd.
    
    +--calico  # root namespace
       |
       |--v1
       |  |--config
       |  |  |--LogFilePath       # the file path for the felix log file.
       |  |  |--IpInIpEnabled     # whether IPIP is enabled
       |  |  |--LogSeverityScreen # the log severity for logs written to stdout/stderr
       |  |  |--InterfacePrefix   # the prefix for Calico interface names
       |  |  |--LogSeverityFile   # Log severity level for writing to file e.g. "DEBUG"
       |  |  `-- ... # Other Felix options are available, and many of these options
       |  |          # can be specified as host-specific.   
       |  |--host
       |  |  `--<hostname>      # one for each Docker host in the cluster
       |  |     |--config       # Host level config
       |  |     |  |--...
       |  |     |  `--marker 
       |  |     |--bird_ip      # the host IP (IPv4) [to be retired]
       |  |     |--workload
       |  |     |  `--<orchestrator-id>  # E.g. docker, openstack, k8s
       |  |     |     `--<container-id>  # one for each container on the Docker Host
       |  |     |        `--endpoint
       |  |     |           `--<endpoint-id>  # JSON endpoint config (see below)
       |  |     `--endpoint
       |  |        `--<endpoint-id> # Host endpoint
       |  |--policy
       |  |  `--profile
       |  |     `--<profile-id>  # Unique string name
       |  |        |--tags  # JSON list of tags
       |  |        `--rules  # JSON rules config (see below)
       |  `--ipam  # IP Pool configuration
       |     |--v4
       |     |   `--pool
       |     |      `--<CIDR>  # One per pool, key is CIDR with '/' replaced
       |     |                 # by '-', value is JSON IP Pool object (see below)
       |     `--v6
       |         `--pool
       |            `--<CIDR>  # One per pool, key is CIDR with '/' replaced
       |                       # by '-', value is JSON IP Pool object (see below)
       |--ipam/v2 # IPAM configuration and assignment data
       |  |--assignment
       |  |  |--ipv4
       |  |  |  `--block
       |  |  |      `--<CIDR>  # One per block, key is CIDR with '/' replaced
       |  |  |                 # by '-', value is JSON Allocation Block object (see below)
       |  |  `--ipv6  
       |  |     `--block
       |  |         `--<CIDR>  # One per block, key is CIDR with '/' replaced
       |  |                    # by '-', value is JSON Allocation Block object (see below)
       |  |--handle
       |  |  `--<Handle ID>    # One per handle, value is JSON Allocation Handle
       |  |                    # object (see below)
       |  |--host
       |  |  `--<hostname>
       |  |     |--ipv4
       |  |     |  `--block
       |  |     |     `--<CIDR>   # CIDR matching the Allocation Block with this host
       |  |     |                 # affinity.  No value stored.
       |  |     `--ipv6  
       |  |     |  `--block
       |  |     |     `--<CIDR>   # CIDR matching the Allocation Block with this host
       |  |     |                 # affinity.  No value stored.
       `--bgp/v1  # BGP Configuration
          |--global
          |  |--as_num    # the default BGP AS number for the nodes
          |  |--node_mesh # JSON node-to-node mesh configuration (see below)
          |  |--peer_v4   # Global IPv4 BGP peers (all nodes peer with)
          |  |  `--<BGP peer IPv4 address>  # JSON BGP peer configuration (see below)
          |  `--peer_v6   # Global IPv6 BGP peers (all nodes peer with)
          |     `--<BGP peer IPv6 address>  # JSON BGP peer configuration (see below)
          `--host
             `--<hostname>  # one for each Docker host in the cluster
                |--ip_addr_v4 # the IP address BIRD listens on
                |--ip_addr_v6 # the IP address BIRD6 listens on
                |--as_num     # the AS number for this host
                |--peer_v4    # Host specific IPv4 BGP peers
                |  `--<BGP peer IPv4 address>  # JSON BGP peer configuration (see below)
                `--peer_v6  # Host specific IPv6 BGP peers
                   `--<BGP peer IPv6 address>  # JSON BGP peer configuration (see below)

## Objects

Calico focuses on the following major object types, stored in etcd:

#### endpoints

An endpoint object represents a single source+sink of data in a
Calico network; for example, the virtual NIC of a VM or a host's
Linux interface. A single virtual machine, container or host may own
multiple endpoints (e.g. if it has multiple vNICs). See
[endpoints](#endpoints) for more.

#### security profiles

A security profile encapsulates a specific set of security rules to
apply to an endpoint. Each endpoint can reference one or more
[security profiles](#security-profiles).

#### security policies

Similarly, a security policy contains a set of security rules to apply.
Security policies allow a rich, ordered security model, which can override
the security profiles directly referenced by an endpoint.

Each security policy has a selector predicate, such as
`type == 'webserver' && role == 'frontend'`, that picks out the endpoints
it should apply to, and an ordering number that specifies the policy's
priority. For each endpoint, Calico applies the security policies that
apply to it, in priority order, and then that endpoint's security profiles.

See [Security policy](#selector-based-security-policy) for more.

The structure of all of this information can be found below.

### Endpoints

The Calico datamodel supports two types of endpoint:

-   Workload endpoints refer to interfaces attached to workloads such as
    VMs or containers, which are running on the host that is running
    Calico's agent, Felix. Calico identifies such interfaces by a name
    prefix; for example OpenStack VM interfaces always start
    with "tap...". By default, Calico blocks all traffic to and from
    workload interfaces.

    Each workload endpoint is stored in an etcd key that matches the
    following pattern:

        /calico/v1/host/<hostname>/workload/<orchestrator_id>/<workload_id>/endpoint/<endpoint_id>

-   Host endpoints refer to the "bare-metal" interfaces attached to the
    host that is running Calico's agent, Felix. By default, Calico
    doesn't apply any policy to such interfaces.

    Each host endpoint is stored in an etcd key that matches the
    following pattern:

        /calico/v1/host/<hostname>/endpoint/<endpoint_id>

The parameters in the paths have the following meanings:

`hostname`: the hostname of the compute server

`orchestrator_id`: for workload endpoints only, the name of the orchestrator that owns the endpoint, e.g. `"docker"` or `"openstack"`.

`workload_id`:   for workload endpoints only, an identifier provided 
by the orchestrator to relate multiple endpoints that belong to the same
workload (e.g. a single VM).

`endpoint_id` an (opaque) identifier for a specific endpoint

### Workload endpoints

For workload endpoints, the object stored is a JSON blob with the
following structure:

```
{
  "state": "active|inactive",
  "name": "<name of linux interface>",
  "mac": "<MAC of the interface>",
  "profile_ids": ["<profile_id>", ...],
  "ipv4_nat": [
    {"int_ip": "198.51.100.17", "ext_ip": "192.168.0.1"},
    ...
  ],
  "ipv4_nets": [
    "198.51.100.17/32",
    ...
  ],
  "ipv6_nat": [
    {"int_ip": "2001:db8::19", "ext_ip": "2001::2"},
    ...
  ],
  "ipv6_nets": [
    "2001:db8::19/128",
    ...
  ],
  "ipv4_gateway": "<IP address>",
  "ipv6_gateway": "<IP address>",
  "labels": {
    "<key>": "<value>",
    "<key>": "<value>",
    ...
  }
}
```

The various properties in this object have the following meanings:

`state`: one of "active" or "inactive". If "active", the endpoint should be
able to send and receive traffic: if inactive, it should not.

`name`: the name of the Linux interface on the host: for example, `tap80`.

`mac`: the MAC address of the endpoint interface.

`profile_ids`: a list of identifiers of [security profiles](#selector-based-security-policy) 
objects that apply to this endpoint. Each profile is applied to packets 
in the order that they appear in this list.

`ipv4_nat`: a list of 1:1 NAT mappings to apply to the endpoint. Inbound
connections to ext_ip will be forwarded to int_ip. Connections
initiated from int_ip will not have their source address changed,
except when an endpoint attempts to connect one of its own ext_ips.
Each int_ip must be associated with the same endpoint
via ipv4_nets.

`ipv4_nets`: a list of IPv4 subnets allocated to this endpoint. IPv4 packets will
only be allowed to leave this interface if they come from an address
in one of these subnets.

> **NOTE**
>
> Currently only /32 subnets are supported.

`ipv6_nat`: a list of 1:1 NAT mappings to apply to the endpoint. Inbound
connections to ext_ip will be forwarded to int_ip. Connections
initiated from int_ip will not have their source address changed,
except when an endpoint attempts to connect one of its own ext_ips.
Each int_ip must be associated with the same endpoint
via ipv6_nets.

`ipv6_nets`: a list of IPv6 subnets allocated to this endpoint. IPv6 packets will
only be allowed to leave this interface if they come from an address
in one of these subnets.

> **NOTE**
>
> Currently only /128 subnets are supported.

`ipv4_gateway`: the gateway IPv4 address for traffic from the VM.

`ipv6_gateway`: the gateway IPv6 address for traffic from the VM.

`labels`: An optional dict of string key-value pairs. Labels are used to
attach useful identifying information to endpoints. It is expected
that many endpoints share the same labels. For example, they could
be used to label all "production" workloads with "deployment=prod"
so that security policy can be applied to production workloads.

If `labels` is missing, it is treated as if there was an empty dict.

### Host endpoints

For host enpdoints, the object stored is a JSON blob of the following
form; the fields are described below:

```
{
  "name": "<name of linux interface>",

  "expected_ipv4_addrs": ["10.0.0.0", ...],
  "expected_ipv6_addrs": ["2201:db8::19", ...],

  "profile_ids": ["<profile_id>", ...],

  "labels": {
    "<key>": "<value>",
    "<key>": "<value>",
    ...
  }
}
```

The various properties in this object have the following meanings:

`name` Required if none of the `expected_ipvX_addrs` fields are present:
the name of the interface to apply policy to; for example "eth0". If
"name" is not present then at least one expected IP must
be specified.

`expected_ipv4_addrs` and `expected_ipv6_addrs`: At least one required 
if `name` is not present: the expected local IP address of the 
endpoint. If `name` is not present, Calico will look for an interface 
matching *any* of the IPs in the list and apply policy to that.

`profile_ids`: a list of identifiers of [security profile](#selector-based-security-policy)
objects that apply to this endpoint. Each profile is applied to packets
in the order that they appear in this list.

`labels`: An optional dict of string key-value pairs. Labels are used to
attach useful identifying information to endpoints. It is expected
that many endpoints share the same labels. For example, they could
be used to label all "production" workloads with "deployment=prod"
so that security policy can be applied to production workloads.

    If `labels` is missing, it is treated as if there was an empty dict.

> **NOTE**
>
> When using the `src_selector|tag` or `dst_selector|tag` match
> criteria in a firewall rule, Calico converts the selector into
> a set of IP addresses. For host endpoints, the
> `expected_ipvX_addrs` fields are used for that purpose. (If
> only the interface name is specified, Calico does not learn
> the IP of the interface for use in match criteria.)
>

### Security Profiles

Each security profile is split up into three bits of data: 'rules',
'tags' and 'labels'.

The 'rules' are an ordered list of ACLs, specifying what should be done
with specific kinds of IP traffic. Traffic that matches a set of rule
criteria will be accepted or dropped, depending on the rule.

The 'tags' are a list of classifiers that apply to each endpoint that
references the profile. The purpose of the tags is to allow for rules in
other profiles/policies to refer to profiles by name, rather than by
membership.

Finally, labels contains a JSON dict with a set of key/value labels (as
described above). The labels on a profile are inherited by all the
endpoints that directly reference that profile and they can be used in
selectors as if they were directly applied to the endpoint. 'labels' is
optional.

For each profile, the rules, tags and labels objects are stored in
different keys, of the form:

    /calico/v1/policy/profile/<profile_id>/rules
    /calico/v1/policy/profile/<profile_id>/tags
    /calico/v1/policy/profile/<profile_id>/labels

### Selector-based security policy

In addition to directly-referenced security profiles, Calico supports an
even richer security model that we call "policies". The richer model 
consists of a series of explicitly ordered "policies".  Each policy has 
a Boolean selector expression that decides whether it applies to a 
given endpoint. Selector expressions match against an endpoint's labels.

Each policy must do one of the following:

-   Match the packet and apply an "allow" action; this immediately
    accepts the packet, skipping all further policies. 
-   Match the packet and apply a "deny" action; this drops the packet
    immediately, skipping all further policies.
-   Fail to match the packet; in which case the packet proceeds to the
    next policy. If there are no more policies then the packet is 
    dropped.

> **NOTE**
>
> If no policies match an endpoint then the packet skips 
> selector-based policy. The "default deny" behavior described above
> only applies once one of the policies matches an endpoint.
>

Calico renders the security policy for each endpoint individually and
only the policies that have matching selectors are rendered.  This ensures
that the number of rules that actually need to be inserted into the kernel is
proportional to the number of local endpoints rather than the total amount of
policy.

Selector-based security policies are stored in etcd in the keys of the form:

    /calico/v1/policy/tier/default/policy/<policy_id>

The security policy itself is very similar to the `rules` JSON dict that
is used for policy, with the addition of a selector and order of its
own:

    {
        "selector": "<selector-expression>",
        "order": <number>|"default",
        "inbound_rules": [{<rule>}, ...],
        "outbound_rules": [{<rule>}, ...]
        "untracked": <boolean>
    }

> **NOTE**
>
> Security policies do not have an associated `labels` or `tags`
> object.
>

Policies with lower values for "order" are applied first.

Selector expressions follow this syntax:

    label == "string_literal"  ->  comparison, e.g. my_label == "foo bar"
    label != "string_literal"   ->  not equal; also matches if label is not present
    label in { "a", "b", "c", ... }  ->  true if the value of label X is one of "a", "b", "c"
    label not in { "a", "b", "c", ... }  ->  true if the value of label X is not one of "a", "b", "c"
    has(label_name)  -> True if that label is present
    ! expr -> negation of expr
    expr && expr  -> Short-circuit and
    expr || expr  -> Short-circuit or
    ( expr ) -> parens for grouping
    all() or the empty selector -> matches all endpoints.

Label names are allowed to contain alphanumerics, `-`, `_` and `/`.
String literals are more permissive but they do not support escape
characters.

Examples (with made-up labels):

    type == "webserver" && deployment == "prod"
    type in {"frontend", "backend"}
    deployment != "dev"
    ! has(label_name)

### Rules

The 'rules' key contains the following JSON-encoded data:

```
{
  "inbound_rules": [{<rule>}, ...],
  "outbound_rules": [{<rule>}, ...]
}
```

Two lists of rules objects, one applying to traffic destined for that
endpoint (`inbound_rules`), one applying to traffic emitted by that
endpoint (`outbound_rules`).

Each rule sub-object has the following JSON-encoded structure:

```
{
  # Positive protocol match: required if matching (even negatively
  # on ports).
  "protocol": "tcp|udp|icmp|icmpv6|<number>",
  
  # Positive matches:
  "src_tag": "<tag_name>",
  "src_selector": "<selector expression>",
  "src_net": "<CIDR>",
  "src_ports": [1234, "2048:4000"],
  "dst_tag": "<tag_name>",
  "dst_net": "<CIDR>",
  "dst_ports": [1234, "2048:4000"],
  "icmp_type": <int>, "icmp_code": <int>,  # Treated together, see below.

  # Negated matches:
  "!protocol": ...,
  "!src_tag": ...,
  "!src_selector": ...,
  "!src_net": ...,
  "!src_ports": ...,
  "!dst_tag": ...,
  "!dst_net": ...,
  "!dst_ports": ...,
  "!icmp_type": ..., "!icmp_code": ...,  # Treated together, see below.

  # If present, "log_prefix" causes the matched packet to be logged
  # with the given prefix.
  "log_prefix": "<log-prefix>",

  "action": "deny | allow",
}
```

Each positive match criteria has a negated version, prefixed with "!".
All the match criteria within a rule must be satisfied for a packet to
match. A single rule can contain the positive and negative version of a
match and both must be satisfied for the rule to match.

All of these properties are optional but some have dependencies (such as
requiring the protocol to be specified):

`protocol`: if present, restricts the rule to only apply to traffic of a
specific IP protocol. Required if `*_ports` is used (because ports
only apply to certain protocols).

    Must be one of these string values: `"tcp"`, `"udp"`, `"icmp"`,
    `"icmpv6"`, `"sctp"`, `"udplite"` or an integer in the range 1-255.

`src_tag` if present, restricts the rule to only apply to traffic that
originates from endpoints that have profiles with the given tag
in them.

`src_net`: if present, restricts the rule to only apply to traffic that
originates from IP addresses in the given subnet.

`src_selector`: if present, contains a selector expression as described
in [Selector-based security policy](#selector-based-security-policy). Only traffic
that originates from endpoints matching the selector will be matched.

> **WARNING**
>
> In addition to the negative version of "src_selector" (which
> is "!src_selector") the selector expression syntax itself
> supports negation. The two types of negation are
> subtly different. One negates the set of matched endpoints,
> the other negates the whole match:
>
> `"src_selector": !has(my_label)` matches packets that are from
> other Calico-controlled endpoints that **do not** have the
> label "my_label".
>
> `"!src_selector": has(my_label)` matches packets that are not from
> Calico-controlled endpoints that **do** have the
> label "my_label".
>
> The effect is that the latter will accept packets from non-Calico
> sources whereas the former is limited to packets from
> Calico-controlled endpoints.

`src_ports`: if present, restricts the rule to only apply to traffic that has a
source port that matches one of these ranges/values. This value is a
list of integers or strings that represent ranges of ports.

Since only some protocols have ports, requires the (positive)
`protocol` match to be set to `"tcp"` or `"udp"` (even for a
negative match).

`dst_tag`: if present, restricts the rule to only apply to traffic that is
destined for endpoints that have profiles with the given tag
in them.

`dst_selector`: if present, contains a selector expression as described
in [Selector-based security policy](#selector-based-security-policy). Only traffic
that is destined for endpoints matching the selector will be matched.

> **WARNING**
>
> The subtlety described above around negating `"src_selector"`
> also applies to `"dst_selector"`.
>

`dst_net`: if present, restricts the rule to only apply to traffic that is
destined for IP addresses in the given subnet.

`dst_ports`: if present, restricts the rule to only apply to traffic that is
destined for a port that matches one of these ranges/values. This
value is a list of integers or strings that represent ranges
of ports.

Since only some protocols have ports, requires the (positive)
`protocol` match to be set to `"tcp"` or `"udp"` (even for a
negative match).

`icmp_type` and `icmp_code`: if present, restricts the rule to apply 
to a specific type and code of ICMP traffic (e.g. `"icmp_type8": 8` 
would correspond to ICMP Echo Request, better known as ping traffic). 
May only be present if the (positive) `protocol` match is set to 
`"icmp"` or `"icmpv6"`.

If `icmp_code` is specified then `icmp_type` is required. This is a
technical limitation imposed by the kernel's iptables firewall,
which Calico uses to enforce the rule.

> **WARNING**
>
> Due to the same kernel limiation, the negated versions of the
> ICMP matches are treated together as a single match. A rule
> that uses `!icmp_type` and `!icmp_code` together will match
> all ICMP traffic apart from traffic that matches **both** type
> and code.
>
    
`log_prefix`: if present, in addition to doing the configured action, 
Calico will log the packet with this prefix. The current implementation 
uses iptables LOG action, which results in a log to syslog.

For iptables compatibility, Calico will truncate the prefix to 27 
characters and limit the character set.
  
`action`: what action to take when traffic matches this rule. One of `deny`,
which drops the packet immediately, `allow`, which accepts the
packet unconditionally and `log`, which logs the packet (to syslog
and continues processing more rules.

### Tags

The value of the tag key is a JSON list of tag strings, as shown below:

```
["A", "B", "C", ...]
```

Each tag in this list applies to every endpoint that is associated with
this policy. These tags can be referred to by rules, as shown above.

A single tag may be associated with multiple security profiles, in which
case it expands to reference all endpoints in all of those profiles.

### IP pool configuration

The IP pool configuration stored at

    /calico/v1/ipam/v4/pool/<CIDR> and
    /calico/v1/ipam/v6/pool/<CIDR>

is a JSON blob in this form:

    {
      "cidr": "<CIDR of pool - eg. 192.168.0.0/16 or fd80:24e2:f998:72d6::/64>",
      "ipip": "<IPIP device name if IPIP configured for the pool - usually tunl0>",
      "masquerade": true|false
    }

The ipip field is only included if IPIP is enabled for this pool.  IPIP is only supported on IPv4 pools.  

The masquerade field enables NAT for outbound traffic.  If omitted, masquerade defaults to false.

### Allocation Block configuration

The Allocation Block configuration stored at

    ipam/v2/assignment/ipv4/block/<CIDR> and
    ipam/v2/assignment/ipv6/block/<CIDR> and

is a JSON blob in this form:

    {
        "cidr": "192.168.0.0/24",
        "affinity": "host:calico-host-01",
        "allocations": [0, 0, 0, 1, 2, 2, nil, nil, nil, nil, ...],
        "attributes": [
            {
                "primary": "0cd47986-24ad-4c00-b9d3-5db9e5c02028",
                "secondary": {
                    "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a",
                    "email": "spike@projectcalico.org"
                }
            },
            {
                "primary": "3465987ac-8975-987qr8789725875-98275",
                "secondary": {
                    "container-name": "sandy_sabin",
                    "email": "spike@projectcalico.org"
                }
            },
            {
                "primary": "adf4589-11ab-c519-af11-098fade2190798",
                "secondary": {
                    "rack": "01"
                }
            }
        ] 
    }

where

-  *cidr* - The block prefix in CIDR format.
-  *affinity* - The host with affinity to this block.
-  *allocations* - A fixed length array with one entry for every address in the
   block.  Nil means unallocated.  A non-negative integer indicates the address
   is allocated, and is the index into the attributes array for the attributes
   assigned to the allocation.
-  *attributes* - List of dictionaries of attributes for allocations.
   
### JSON Allocation Handles configuration

The Allocation Handle configuration stored at

    ipam/v2/assignment/handle/<Handle ID>

is a JSON blob in this form:

    {
        "id": <string handle ID>,
        "block": {
            "192.168.10.0/24": 4,
            "2001:abcd:def0::/120": 3
        }
    }

where

-  *id* - The handle ID
-  *block* - A dictionary mapping Allocation Block CIDRs with the count of
   allocations within that block associated with this handle.

### JSON node-to-node mesh configuration

The configuration controlling whether a full node-to-node BGP mesh is set up
automatically.

The node-to-node mesh configuration stored at

    /calico/v1/config/bgp_node_mesh

is a JSON blob in this form:

    {
      "enabled": true|false
    }

If the key is missing from etcd, the node-to-node mesh is enabled by default.

### JSON BGP Peer configuration

Explicit BGP peers are configurable globally (all hosts peer with these), or
for a specific host.

The full set of peers for a specific host comprises all other hosts (if the
node-to-node mesh is enabled), the set of global peers and the set of peers
specific to the host.

The configuration for the global BGP peers is stored at

    /calico/v1/config/bgp_peer_v4/<BGP peer IPv4 address>

and

    /calico/v1/config/bgp_peer_v6/<BGP peer IPv6 address>

The configuration for the host node specific BGP peers is stored at

    /calico/v1/host/<hostname>/bgp_peer_v4/<BGP peer IPv4 address>

and

    /calico/v1/host/<hostname>/bgp_peer_v6/<BGP peer IPv6 address>

In all cases, the data is a JSON blob in the form:

    {
      "ip": "IP address of BGP Peer",
      "as_num": "The AS Number of the peer"
    }

