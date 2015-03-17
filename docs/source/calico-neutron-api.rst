How Calico Interprets Neutron API Calls
=======================================

When running in an OpenStack deployment, Calico receives and interprets certain
Neutron API actions, in order to program those actions down into the network.
However, because Calico is substantially simpler than much of what Neutron
generally allows (see :doc:`opens-external-conn`) and because it's a purely
layer 3 model (see :doc:`datapath`), not all Neutron API calls will have the
same effect as they would with other backends.

This document will go into detail on the full range of Neutron API calls, and
will discuss the effect they have on the network. It uses the
`Networking API v2.0`_ document from OpenStack as a basis for listing the
various objects that the Neutron API uses: see that document for more
information about what Neutron expects more generally.

.. _Networking API v2.0: http://developer.openstack.org/api-ref-networking-v2.html

.. _neutron-api-networks:

Networks
--------

Networks are the basic networking concept in Neutron. A Neutron network is
considered to be roughly equivalent to a physical network in terms of function:
it defines a single layer 2 connectivity graph.

In vanilla Neutron, these can map to the underlay network in various ways,
either by being encapsulated over it or by being directly mapped to it.

Generally speaking, Networks can be created by all tenants. The administrator
tenant will generally create some public Networks that map to the underlay
network directly for providing floating IPs: other tenants will create their
own private networks as necessary.

In Calico, because all traffic is L3 and routed, the role of Network as L2
connectivity domain is not helpful. Therefore in Calico networks are simply
containers for subnets. Best practices for operators configuring networks in
Calico deployments can be found in :ref:`opens-external-conn-setup`.

Network creation events on the API are supported by Calico, but are no-op
actions: no programming occurs in response to them.

Extended Attributes: Provider Networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Provider networks are not used in Calico deployments. Setting provider network
extended attributes will have no effect. See :doc:`opens-external-conn` to
understand why provider networks are not needed.

Subnets
-------

Subnets are child objects of Networks. In Neutron, a Subnet is a collection of
IP addresses and other network configuration (e.g. DNS servers) that is
associated with a single Neutron Network. A single Network may have multiple
Subnets associated with it. Each subnet represents either an IPv4 or IPv6 block
of addresses.

Best practices for configuring subnets in Calico deployments can be found in
:ref:`opens-external-conn-setup`.

In Calico, these roles for the subnet are preserved in their entirety. All
properties associated with these subnets are preserved and remain meaningful
except for:

``host_routes``
  These have no effect, as the compute nodes will route traffic immediately
  after it egresses the VM.

Ports
-----

In vanilla Neutron, a port represents a connection from a VM to a single layer
2 Network. Obviously, the meaning of this object changes in a Calico network:
instead, a port is a connection from a VM to the single shared layer 3 network
that Calico builds.

All properties on a port work as normal, except for the following:

``network_id``
  The network ID still controls which network the port is attached to, and
  therefore still controls which subnets it will be placed in. However, as per
  the note in :ref:`neutron-api-networks`, the network that a port is placed in
  does not affect which machines in the network it can contact.

Extended Attributes: Port Binding Attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``binding:host-id`` attribute works as normal. The following notes apply to
the other attributes:

``binding:vif_details``
  No fields in this property are used by Calico, and setting them will have no
  effect.

``binding:profile``
  This is unused in Calico.

``binding:vnic_type``
  This field, if used, must be set to ``normal``. If set to any other value,
  Calico will not correctly function.

Quotas
------

Neutron quotas function unchanged.

Security Groups
---------------

Security groups in vanilla OpenStack provide packet filtering processing to
individual ports. They can be used to limit the traffic a port may issue.

In Calico, security groups have all the same function. Additionally, they serve
to provide the connectivity-limiting function that in vanilla OpenStack is
provided by Networks. For more information, see :doc:`security-model`.

All the attributes of security groups remain unchanged in Calico.

Layer 3 Routing: Routers and Floating IPs
-----------------------------------------

Layer 3 routing objects are divided into two categories: routers and floating
IPs. Neither of these objects are supported by Calico: they simply aren't
required. For more information, see :doc:`opens-external-conn`.

Any attempt to create these objects will fail, as Calico does not set up any
Neutron L3 Agents.

LBaaS (Load Balancer as a Service)
----------------------------------

Load Balancer as a Service does not function in a Calico network. Any attempt
to create one will fail.

.. note:: It is possible that in a future version of Calico LBaaS may be
          functional. Watch this space.
