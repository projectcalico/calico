.. # Copyright (c) Metaswitch Networks 2015. All rights reserved.
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
Calico components to set up the Calico network.

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
  network. A single virtual machine or container may own multiple endpoints
  (e.g. if it has multiple vNICs). See :ref:`endpoint-data` for more.

security profiles
  A security profile is an object that encapsulates a specific security policy
  that can be applied to endpoints. See :ref:`security-profile-data` for more.

The structure of all of this information can be found below.


.. _endpoint-data:

Endpoints
~~~~~~~~~

Each endpoint object is stored in an etcd key that matches the following
pattern::

    /calico/host/<hostname>/workload/<orchestrator_id>/<workload_id>/endpoint/<endpoint_id>

where the properties have the following meanings:

``hostname``
  the hostname of the compute server

``orchestrator_id``
  the name of the orchestrator that owns the endpoint, e.g. ``"docker"`` or
  ``"openstack"``.

``workload_id``
  an identifier provided by the orchestrator to relate multiple endpoints that
  belong to the same workload (e.g. a single VM).

``endpoint_id``
  an identifier for a specific endpoint

The object stored is a JSON blob with the following structure:

.. code-block:: json

    {
      "state": "active|inactive",
      "name": "<name of linux interface>",
      "mac": "<MAC of the interface>",
      "profile_id": "<profile_id>",
      "ipv4_nets": [
        "198.51.100.17/32",
        …
      ],
      "ipv6_nets": [
        "2001:db8::19/128",
        …
      ],
      "ipv4_gateway": "<IP address>",
      "ipv6_gateway": "<IP address>"
    }

The various properties in this object have the following meanings:

``state``
  one of "active" or "inactive". If "active", the endpoint should be able to
  send and receive traffic: if inactive, it should not.

``name``
  the name of the Linux interface on the host: for example, ``tap80``.

``mac``
  the MAC address of the endpoint interface.

``profile_id``
  the identifier of a single :ref:`security-profile-data` object, which applies
  to this endpoint.

``ipv4_nets``
  a list of IPv4 subnets allocated to this endpoint. IPv4 packets will only be
  allowed to leave this interface if they come from an address in one of these
  subnets.

  .. note:: Currently only /32 subnets are supported.

``ipv6_nets``
  a list of IPv6 subnets allocated to this endpoint. IPv6 packets will only be
  allowed to leave this interface if they come from an address in one of these
  subnets.

  .. note:: Currently only /128 subnets are supported.

``ipv4_gateway``
  the gateway IPv4 address for traffic from the VM.

``ipv6_gateway``
  the gateway IPv6 address for traffic from the VM.


.. _security-profile-data:

Security Profiles
~~~~~~~~~~~~~~~~~

Each security profile is split up into two bits of data: 'rules' and 'tags'.
The 'rules' are an ordered list of ACLs, specifying what should be done with
specific kinds of IP traffic. Traffic that matches a set of rule criteria will
be accepted or dropped, depending on the rule. The tags are a list of
classifiers that apply to each endpoint in the profile. The purpose of the
tags is to allow for rules in other policies to refer to profiles by name,
rather than by membership.

For each profile, the rules objects and tag objects are stored in different
keys, of the form::

    /calico/policy/profile/<profile_id>/rules
    /calico/policy/profile/<profile_id>/tags

Additionally, each profile keeps a count of the number of endpoints that
reference it. This allows for garbage collection of profiles without requiring
that components regularly scan all of etcd for profile membership. This count
is stored at::

    /calico/policy/profile/<profile_id>/refcount

When creating a security profile, the ``refcount`` key must be atomically
initialised first, to avoid data races.

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
      "protocol": "tcp|udp|icmp|icmpv6",
      "src_tag": "<tag_name>",
      "src_net": "<CIDR>",
      "src_ports": [1234, "2048:4000"],
      "dst_tag": "<tag_name>",
      "dst_net": "<CIDR>",
      "dst_ports": [1234, "2048:4000"],
      "icmp_type": <int>,
      "action": "deny|allow",
    }

The properties in the rules object have the following meaning. All of these
properties are optional:

``protocol``
  if present, restricts the rule to only apply to traffic of a specific
  protocol.

``src_tag``
  if present, restricts the rule to only apply to traffic that originates from
  endpoints that have profiles with the given tag in them.

``src_net``
  if present, restricts the rule to only apply to traffic that originates from
  IP addresses in the given subnet.

``src_ports``
  if present, restricts the rule to only apply to traffic that has a source
  port that matches one of these ranges/values. This value is a list of
  integers or strings that represent ranges of ports.

``dst_tag``
  if present, restricts the rule to only apply to traffic that is destined for
  endpoints that have profiles with the given tag in them.

``dst_net``
  if present, restricts the rule to only apply to traffic that is destined for
  IP addresses in the given subnet.

``dst_ports``
  if present, restricts the rule to only apply to traffic that is destined for
  a port that matches one of these ranges/values. This value is a list of
  integers or strings that represent ranges of ports.

``icmp_type``
  if present, restricts the rule to apply to a specific type of ICMP traffic
  (e.g. 8 would correspond to ICMP Echo Request, better known as ping traffic).
  May only be present if ``protocol`` is set to ``"icmp"`` or ``"icmpv6"``.

``action``
  what action to take when traffic matches this rule. If not specified,
  defaults to ``"allow"``.

Tags
^^^^

The value of the tag key is a JSON list of tag strings, as shown below:

.. code-block:: json

   ["A", "B", "C", ...]

Each tag in this list applies to every endpoint that is associated with this
policy. These tags can be referred to by rules, as shown above.

A single tag may be associated with multiple security profiles, in which case
it expands to reference all endpoints in all of those profiles.

Reference Count
^^^^^^^^^^^^^^^

The reference count is an unsigned integer that records the number of endpoints
that are using this security profile. This is not stored as JSON, but as an
integer. Because etcd does not have typed data, the data is technically a
base-10 integer string: writing any other data into this key is an error.

Changes to this key must *always* be performed using etcd's atomic
compare-and-swap function, including writing it at profile creation time.

Care must be taken here: it's possible that an attempt to increment the
reference count of a profile will find that the profile does not exist
(because it got deleted) in which case it will need creating. Alternatively, it
is possible that an attempt to create a profile will find that it already
exists, and so instead the reference count will need incrementing. Be cautious.
