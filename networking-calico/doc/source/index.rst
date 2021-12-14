.. networking-calico documentation master file, created by
   sphinx-quickstart on Tue Jul  9 22:26:36 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

networking-calico
=================

networking-calico is the Calico sub-project that provides 'Calico' connectivity
and security in an OpenStack/Neutron cloud.  It provides the extra pieces that
are needed to integrate Calico into OpenStack, namely a Neutron server driver
or plugin, and a modified DHCP agent.

Calico (http://www.projectcalico.org/) uses IP routing to provide
connectivity - in the form of a flat IP network - between the workloads in a
data center that provide or use IP-based services - whether VMs, containers or
bare metal appliances; and iptables, to impose any desired fine-grained
security policy between those workloads.  Calico thus differs from most other
Neutron backends, which use bridging and tunneling to simulate L2-level
connectivity between the VMs attached to a Neutron network.

Using Calico implies and requires some restrictions on the full generality of
what can theoretically be expressed by the Neutron API and data model.
Specifically:

- Calico only supports IP addresses in a single, flat IP address space.
  Therefore it does not support overlapping IP ranges, or "bring your own
  addressing."  In Neutron API terms, all Calico network subnets must belong to
  the same address scope.

- Calico does not provide layer 2 adjacency even on the same Neutron subnet, so
  raw layer 2 protocols and broadcast do not work with Calico.  In Neutron API
  terms, all Calico networks are :code:`l2_adjacency False`.

- Calico provides connectivity between different networks by default, and
  relies on security group configuration and policy to implement whatever
  network isolation and finer-grained security restrictions are desired.  In
  Neutron API terms, this means that Calico networks must either be external
  provider networks, or be tenant networks that are connected through a Neutron
  router to an external network.

Documentation for installing and using networking-calico can be found at
http://docs.projectcalico.org/master.  Here we maintain docs that may be of
interest about networking-calico's design and implementation.

.. toctree::
   :maxdepth: 2

   implementation-notes
   dhcp-agent

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
