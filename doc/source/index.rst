.. networking-calico documentation master file, created by
   sphinx-quickstart on Tue Jul  9 22:26:36 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

networking-calico
=================

networking-calico is the Neutron 'stadium' sub-project that provides 'Calico'
connectivity and security in an OpenStack/Neutron cloud.

Calico (http://www.projectcalico.org/) uses IP routing to provide connectivity
between the workloads in a data center that provide or use IP-based services -
whether VMs, containers or bare metal appliances; and iptables, to impose any
desired fine-grained security policy between those workloads.  Calico thus
differs from most other Neutron backends, which use bridging and tunneling to
simulate L2-level connectivity between the VMs attached to a Neutron network.

Calico networks also differ semantically from (non-external) Neutron networks,
but are arguably similar to external Neutron networks, in that

- there is automatically east-west reachability between different Calico
  networks, without any need for a Neutron virtual router

- there is automatically potential reachability between any Calico network and
  the outside world (in practice depending on how an operator connects up their
  cloud fabric network, and how their BGP topology gateways routes and traffic
  between the cloud network and the Internet).

networking-calico works today with vanilla Liberty OpenStack (and there is a
DevStack plugin that makes it very easy to try this - see
http://docs.openstack.org/developer/networking-calico/devstack.html).

The remaining issue is just that the Neutron API does not properly describe the
semantics that Calico delivers: Calico's connectivity semantics differ from
what an operator might expect, given the sequence of Neutron API calls that is
made to set up a Calico system.  Work to address this is in progress at
https://review.openstack.org/#/c/238895/.  Please do contribute your opinion
there, if this is of interest to you.

.. toctree::
   :maxdepth: 2

   readme
   devstack
   implementation-notes
   host-routes
   dhcp-agent
   contributing

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
