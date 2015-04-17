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

Security Policy Model
=====================

Calico's current security policy model is syntactically the same as that of
security groups in OpenStack.

.. note:: We have work in progress to replace this model with something more
          flexible, so watch this space, and please let us know if you have
          specific requirements in this area.

Security Groups
---------------

An endpoint is configured, when it is created, to belong to one or more
security groups.  (It is possible for an endpoint to belong to no security
groups, but then it would have no connectivity at all - so probably not very
useful.)  The security groups that an endpoint belongs to can also be updated
later on.

A security group is a collection of rules that may be applied to an endpoint
(i.e. to data coming from or travelling to a particular workload vNIC).  The
default (for both in- and outbound) is always to DENY traffic, so rules specify
exceptions that allow traffic through.  These exceptions carry the following
information::

    allow IPv4|IPv6 [<protocol> [<port range>]] traffic from/to <cidr>|<group>

where `<cidr>` is an IPv4 or IPv6 prefix, and `<group>` specifies either this
or another security group, and means all of the remote endpoints that belong to
that group.

If a workload has multiple vNICs - aka endpoints - each of those vNICs may
belong to a different set of security groups.

Differences from OpenStack
--------------------------

Although the structure and syntax of the security group information is the
same, there are practical differences between how Calico and OpenStack
interpret this information.

Effective security in OpenStack is actually a product of the interaction
between three kinds of objects: networks, routers and security groups.  Calico,
on the other hand, **only** uses security groups for security configuration;
and networks and routers have no impact.  The following subsections go into
this in more detail, and discuss how these concepts map onto the Calico data
model.

Networks and Routers
~~~~~~~~~~~~~~~~~~~~

As discussed in :ref:`opens-external-conn`, networks and routers are not used
in Calico for connectivity purposes.  Similarly, they serve no security purpose
in a Calico environment.

Calico can provide equivalent functionality to networks and routers using
security groups.  To achieve it, rather than placing all ports that need to
communicate into a single network, place them all in a security group that
allows ingress from and egress to the same security group.

Architecture
------------

.. note:: Following the change to use etcd instead of message queues to
          communicate between components, this document may now contain out of
          date information. We will remedy this in the near future.

At present, the flow of security information proceeds as follows::

    [Configuration in OpenStack or other orchestrator] -(Plugin)-> [Calico network API] -(ACL Manager)-> [Calico ACL API] -(Felix)-> [Programmed IPTables rules]

When a security group is configured, the Calico orchestrator plugin discovers
the new configuration. This configuration is passed over the Calico Network
API to the ACL manager. This component transforms the ACLs if necessary and
then passes them over the Calico ACL API to the relevant Felix agent. That
Felix agent then programs the rules into the kernel using ``iptables`` and
``ipsets`` commands.
