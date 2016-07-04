.. # Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
   #
   #    Licensed under the Apache License, Version 2.0 (the "License"); you may
   #    not use this file except in compliance with the License. You may obtain
   #    a copy of the License at
   #
   #         http://www.apache.org/licenses/LICENSE-2.0
   #
   #    Unless required by applicable law or agreed to in writing, software
   #    distributed under the License is distributed on an "AS IS" BASIS,
   #    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   #    implied. See the License for the specific language governing
   #    permissions and limitations under the License.


Calico etcd Data Model
======================

In Calico, etcd is used as the data store and communication mechanism for all
the Calico components. This data store contains all the information the various
Calico components require to set up the Calico network.

This document discusses the way Calico stores its data in etcd. This data store
and structure acts as Calico's primary external and internal API, granting
developers exceptional control over what Calico does. This document does not
describe the components that read and write this data to provide the
connectivity that endpoints in a Calico network want: for more on that, see
:doc:`architecture`.

.. _etcd: https://github.com/coreos/etcd

Objects
-------

Calico focuses on the following major object types, stored in etcd:

endpoints
  An endpoint object represents a single source+sink of data in a Calico
  network; for example, the virtual NIC of a VM or a host's Linux interface.
  A single virtual machine, container or host may own multiple endpoints
  (e.g. if it has multiple vNICs). See :ref:`endpoint-data` for more.

security profiles
  A security profile encapsulates a specific set of security rules to apply
  to an endpoint. Each endpoint can reference one or more security profiles.
  See :ref:`security-profile-data` for more.

security policies
  Similarly, a security policy contains a set of security rules to apply.
  Security policies allow a tiered security model, which can override the
  security profiles directly referenced by an endpoint.

  Each security policy has a selector predicate, such as
  "type == 'webserver' && role == 'frontend'", that picks out the endpoints
  it should apply to, and an ordering number that specifies the policy's
  priority. For each endpoint, Calico applies the security policies that
  apply to it, in priority order, and then that endpoint's security profiles.

  See :ref:`security-policy-data` for more.

The structure of all of this information can be found below.


.. _endpoint-data:

Endpoints
~~~~~~~~~

The Calico datamodel supports two types of endpoint:

- Workload endpoints refer to interfaces attached to workloads such as VMs or
  containers, which are running on the host that is running Calico's agent,
  Felix.  Calico identifies such interfaces by a name prefix; for example
  OpenStack VM interfaces always start with "tap...".  By default, Calico
  blocks all traffic to and from workload interfaces.

  Each workload endpoint is stored in an etcd key that matches the following
  pattern::

      /calico/v1/host/<hostname>/workload/<orchestrator_id>/<workload_id>/endpoint/<endpoint_id>


- Host endpoints refer to the "bare-metal" interfaces attached to the host
  that is running Calico's agent, Felix.  By default, Calico doesn't apply
  any policy to such interfaces.

  Each host endpoint is stored in an etcd key that matches the following
  pattern::

      /calico/v1/host/<hostname>/endpoint/<endpoint_id>

The parameters in the paths have the following meanings:

``hostname``
  the hostname of the compute server

``orchestrator_id``
  for workload endpoints only, the name of the orchestrator that owns the
  endpoint, e.g. ``"docker"`` or ``"openstack"``.

``workload_id``
  for workload endpoints only, an identifier provided by the orchestrator to
  relate multiple endpoints that belong to the same workload (e.g. a single
  VM).

``endpoint_id``
  an (opaque) identifier for a specific endpoint
  
Workload endpoints
^^^^^^^^^^^^^^^^^^

For workload endpoints, the object stored is a JSON blob with the following
structure:

.. code-block:: json

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

The various properties in this object have the following meanings:

``state``
  one of "active" or "inactive". If "active", the endpoint should be able to
  send and receive traffic: if inactive, it should not.

``name``
  the name of the Linux interface on the host: for example, ``tap80``.

``mac``
  the MAC address of the endpoint interface.

``profile_ids``
  a list of identifiers of :ref:`security-profile-data` objects that apply to
  this endpoint. Each profile is applied to packets in the order that they
  appear in this list.

``ipv4_nat``
  a list of 1:1 NAT mappings to apply to the endpoint.  Inbound connections to
  ext_ip will be forwarded to int_ip.  Connections initiated from int_ip will
  not have their source address changed, except when an endpoint attempts to
  connect one of its own ext_ips.  Each int_ip must be associated with the
  same endpoint via ipv4_nets.

``ipv4_nets``
  a list of IPv4 subnets allocated to this endpoint. IPv4 packets will only be
  allowed to leave this interface if they come from an address in one of these
  subnets.

  .. note:: Currently only /32 subnets are supported.

``ipv6_nat``
  a list of 1:1 NAT mappings to apply to the endpoint.  Inbound connections to
  ext_ip will be forwarded to int_ip.  Connections initiated from int_ip will
  not have their source address changed, except when an endpoint attempts to
  connect one of its own ext_ips.  Each int_ip must be associated with the
  same endpoint via ipv6_nets.

``ipv6_nets``
  a list of IPv6 subnets allocated to this endpoint. IPv6 packets will only be
  allowed to leave this interface if they come from an address in one of these
  subnets.

  .. note:: Currently only /128 subnets are supported.

``ipv4_gateway``
  the gateway IPv4 address for traffic from the VM.

``ipv6_gateway``
  the gateway IPv6 address for traffic from the VM.

``labels``
  An optional dict of string key-value pairs. Labels are used to attach useful
  identifying information to endpoints. It is expected that many endpoints
  share the same labels.  For example, they could be used to label all
  "production" workloads with "deployment=prod" so that security policy
  can be applied to production workloads.

  If ``labels`` is missing, it is treated as if there was an empty dict.

Host endpoints
^^^^^^^^^^^^^^

For host enpdoints, the object stored is a JSON blob of the following form;
the fields are described below:

.. code-block:: json

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


The various properties in this object have the following meanings:

``name``
  Required if none of the ``expected_ipvX_addrs`` fields are present: the
  name of the interface to apply policy to; for example "eth0".  If "name" is
  not present then at least one expected IP must be specified.

``expected_ipv4_addrs`` and ``expected_ipv6_addrs``
  At least one required if ``name`` is not present: the expected local IP
  address of the endpoint.  If ``name`` is not present, Calico will look for
  an interface matching *any* of the IPs in the list and apply policy to
  that.

``profile_ids``
  a list of identifiers of :ref:`security-profile-data` objects that apply to
  this endpoint. Each profile is applied to packets in the order that they
  appear in this list.

``labels``
  An optional dict of string key-value pairs. Labels are used to attach useful
  identifying information to endpoints. It is expected that many endpoints
  share the same labels.  For example, they could be used to label all
  "production" workloads with "deployment=prod" so that security policy
  can be applied to production workloads.

  If ``labels`` is missing, it is treated as if there was an empty dict.

  .. note:: When using the ``src_selector|tag`` or ``dst_selector|tag`` match
            criteria in a firewall rule, Calico converts the selector into a
            set of IP addresses.  For host endpoints, the
            ``expected_ipvX_addrs`` fields are used for that purpose.  (If
            only the interface name is specified, Calico does not learn the
            IP of the interface for use in match criteria.)


.. _security-profile-data:

Security Profiles
~~~~~~~~~~~~~~~~~

Each security profile is split up into three bits of data: 'rules', 'tags'
and 'labels'.

The 'rules' are an ordered list of ACLs, specifying what should be done with
specific kinds of IP traffic. Traffic that matches a set of rule criteria will
be accepted or dropped, depending on the rule.

The 'tags' are a list of classifiers that apply to each endpoint that refences
the profile. The purpose of the tags is to allow for rules in other
profiles/policies to refer to profiles by name, rather than by membership.

Finally, labels contains a JSON dict with a set of key/value labels (as
described above).  The labels on a profile are inherited by all the endpoints
that directly reference that profile and they can be used in selectors as
if they were directly applied to the endpoint.  'labels' is optional.

For each profile, the rules, tags and labels objects are stored in different
keys, of the form::

    /calico/v1/policy/profile/<profile_id>/rules
    /calico/v1/policy/profile/<profile_id>/tags
    /calico/v1/policy/profile/<profile_id>/labels


.. _security-policy-data:

Tiered security policy
~~~~~~~~~~~~~~~~~~~~~~

In addition to directly-referenced security profiles, Calico supports an even
richer security model that we call "tiered policy". Tiered policy consists
of a series of explicitly ordered "tiers".  Tiers contain (explicitly
ordered) "policies".  Each policy has a Boolean selector expression
that decides whether it applies to a given endpoint. Selector expressions
match against an endpoint's labels.

Each tier might have a different owner; for example, an enterprise's NetSec
team could install a global black/white list that comes before rules
generated by a Calico plugin::

    tier 1: global "netsec" rules
        policy 1, all endpoints: <global blacklist>
        policy 2, all endpoints: <global whitelist>
        ...
    tier 2: Calico plugin-defined rules
        policy 1, role == "webserver" && deployment == "prod": <prod webserver rules>
    tier 3: ...


Each policy must do one of the following:

- Match the packet and apply a "next-tier" action; this skips the rest of the
  tier, deferring to the next tier (or the explicit profiles if this is the
  last tier.
- Match the packet and apply an "allow" action; this immediately accepts the
  packet, skipping all further tiers and profiles.  This is not recommended
  in general, because it prevents further policy from being executed.
- Match the packet and apply a "deny" action; this drops the packet
  immediately, skipping all further tiers and profiles.
- Fail to match the packet; in which case the packet proceeds to the next
  policy in the tier.  If there are no more policies in the tier then the
  packet is dropped.

.. note:: If no policies in a tier match an endpoint then the packet skips
          the tier completely.  The "default deny" behavior described above
          only applies once one of the profiles in a tier has matched a packet.

Calico implements the security policy for each endpoint individually and
only the policies that have matching selectors are implemented.  This ensures
that the number of rules that actually need to be inserted into the kernel is
proportional to the number of local endpoints rather than the total amount of
policy.  If no policies in a tier match a given endpoint then that tier is
skipped.

Tiered security policies are stored in etcd in the keys of the form::

    /calico/v1/policy/tier/<tier_name>/policy/<policy_id>


Each ``<tier-name>`` directory defines a tier and each tier is required to have
a metadata key inside it::

    /calico/v1/policy/tier/<tier_name>/metadata


The metadata key contains a JSON dict, which currently contains only the order
for the tier::

    {"order": <number>|"default"}


Tiers with higher "order" values are applied after those with lower numbers.
If the ``order`` is omitted or set to "default" then the tier effectively
has infinite order, it will be applied after any other tiers.

The security policy itself is very similar to the ``rules`` JSON dict that is
used for policy, with the addition of a selector and order of its own::

    {
        "selector": "<selector-expression>",
        "order": <number>|"default",
        "inbound_rules": [{<rule>}, ...],
        "outbound_rules": [{<rule>}, ...]
    }


.. note:: Security policies do not have an associated ``labels`` or ``tags``
          object.

Similarly to the tier order, policies with lower values for "order" are
applied first.

Selector expressions follow this syntax::

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


Label names are allowed to contain alphanumerics, ``-``, ``_`` and ``/``.
String literals are more permissive but they do not support escape characters.

Examples (with made-up labels)::

    type == "webserver" && deployment == "prod"
    type in {"frontend", "backend"}
    deployment != "dev"
    ! has(label_name)


Rules
^^^^^

The 'rules' key contains the following JSON-encoded data:

.. code-block:: json

    {
      "inbound_rules": [{<rule>}, ...],
      "outbound_rules": [{<rule>}, ...]
    }

Two lists of rules objects, one applying to traffic destined for that endpoint
(``inbound_rules``), one applying to traffic emitted by that endpoint
(``outbound_rules``).

Each rule sub-object has the following JSON-encoded structure:

.. code-block:: json

    {
      # Positive matches:
      "protocol": "tcp|udp|icmp|icmpv6|<number>",
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

      "action": "deny | allow | next-tier",
    }


Each positive match criteria has a negated version, prefixed with "!". All the
match criteria within a rule must be satisfied for a packet to match.
A single rule can contain the positive and negative version of a match and
both must be satisfied for the rule to match.

All of these properties are optional but some have dependencies (such as
requiring the protocol to be specified):

``protocol``
  if present, restricts the rule to only apply to traffic of a specific IP
  protocol.  Required if ``*_ports`` is used (becuase ports only apply to
  certain protocols).

  Must be one of these string values: ``"tcp"``, ``"udp"``, ``"icmp"``,
  ``"icmpv6"``, ``"sctp"``, ``"udplite"`` or an integer in the range 1-255.

``src_tag``
  if present, restricts the rule to only apply to traffic that originates from
  endpoints that have profiles with the given tag in them.

``src_net``
  if present, restricts the rule to only apply to traffic that originates from
  IP addresses in the given subnet.

``src_selector``
  if present, contains a selector expression as described in
  :ref:`security-policy-data`.  Only traffic that originates from endpoints
  matching the selector will be matched.

  .. warning:: In addition to the negative version of "src_selector" (which
               is "!src_selector") the selector expression syntax itself
               supports negation.  The two types of negation are subtly
               different.  One negates the set of matched endpoints, the other
               negates the whole match:

               ``"src_selector": !has(my_label)`` matches packets that are
               from other Calico-controlled endpoints that **do not** have the
               label "my_label".

               ``"!src_selector": has(my_label)`` matches packets that are
               not from Calico-controlled endpoints that **do** have the
               label "my_label".

               The effect is that the latter will accept packets from
               non-Calico sources whereas the former is limited to packets
               from Calico-controlled endpoints.

``src_ports``
  if present, restricts the rule to only apply to traffic that has a source
  port that matches one of these ranges/values. This value is a list of
  integers or strings that represent ranges of ports.

  Since only some protocols have ports, requires the (positive) ``protocol``
  match to be set to ``"tcp"`` or ``"udp"`` (even for a negative match).

``dst_tag``
  if present, restricts the rule to only apply to traffic that is destined for
  endpoints that have profiles with the given tag in them.

``dst_selector``
  if present, contains a selector expression as described in
  :ref:`security-policy-data`.  Only traffic that is destined for endpoints
  matching the selector will be matched.

  .. warning:: The subtlety described above around negating ``"src_selector"``
               also applies to ``"dst_selector"``.

``dst_net``
  if present, restricts the rule to only apply to traffic that is destined for
  IP addresses in the given subnet.

``dst_ports``
  if present, restricts the rule to only apply to traffic that is destined for
  a port that matches one of these ranges/values. This value is a list of
  integers or strings that represent ranges of ports.

  Since only some protocols have ports, requires the (positive) ``protocol``
  match to be set to ``"tcp"`` or ``"udp"`` (even for a negative match).

``icmp_type`` and ``icmp_code``
  if present, restricts the rule to apply to a specific type and code of ICMP
  traffic (e.g. ``"icmp_type8": 8`` would correspond to ICMP Echo Request,
  better known as ping traffic).  May only be present if the (positive)
  ``protocol`` match is set to ``"icmp"`` or ``"icmpv6"``.

  If ``icmp_code`` is specified then ``icmp_type`` is required.  This is a
  technical limitation imposed by the kernel's iptables firewall, which Calico
  uses to enforce the rule.

  .. warning:: Due to the same kernel limiation, the negated versions of the
               ICMP matches are treated together as a single match.  A rule
               that uses ``!icmp_type`` and ``!icmp_code`` together will match
               all ICMP traffic apart from traffic that matches **both** type
               and code.

``action``
  what action to take when traffic matches this rule. One of ``deny``, which
  drops the packet immediately; ``allow``, which accepts the packet
  unconditionally and ``next-tier``, which, in tiered security policies,
  jumps to the next tier and continues processing.  (In profiles, the
  ``next-tier`` action is a synonym for ``allow``.)

Tags
^^^^

The value of the tag key is a JSON list of tag strings, as shown below:

.. code-block:: json

   ["A", "B", "C", ...]

Each tag in this list applies to every endpoint that is associated with this
policy. These tags can be referred to by rules, as shown above.

A single tag may be associated with multiple security profiles, in which case
it expands to reference all endpoints in all of those profiles.
