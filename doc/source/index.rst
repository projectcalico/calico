.. networking-calico documentation master file, created by
   sphinx-quickstart on Tue Jul  9 22:26:36 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

networking-calico
=================

networking-calico is the Neutron 'stadium' sub-project that provides
'Calico' connectivity and security in an OpenStack/Neutron cloud.

Calico [#]_ uses IP routing to provide connectivity between the
workloads in a data center that provide or use IP-based services -
whether VMs, containers or bare metal appliances; and iptables, to
impose any desired fine-grained security policy between those
workloads.  Calico thus differs from most other Neutron backends,
which use bridging and tunneling to simulate L2-level connectivity
between the VMs attached to a Neutron network.

Calico networks also differ semantically from (non-external) Neutron
networks, but are arguably similar to external Neutron networks, in
that

- there is automatically east-west reachability between different
  Calico networks, without any need for a Neutron virtual router

- there is automatically potential reachability between any Calico
  network and the outside world (in practice depending on how an
  operator connects up their cloud fabric network, and how their BGP
  topology gateways routes and traffic between the cloud network and
  the Internet).

There is an ongoing and lively discussion [#]_ about how best to fully
express the semantics of routing-based networks - including the Calico
case - in the Neutron API and data model.  Please do contribute your
opinion there, if this is of interest to you.

.. [#] http://www.projectcalico.org/
.. [#] https://review.openstack.org/#/c/225384/

.. toctree::
   :maxdepth: 2

   readme
   devstack
   contributing

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
