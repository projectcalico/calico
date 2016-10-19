
.. _floating:

Floating IPs
============

networking-calico includes beta support for floating IPs.  Currently this
requires running Calico as a Neutron core plugin (i.e. :code:`core_plugin =
calico`) instead of as an ML2 mechanism driver.

.. note:: We would like it to work as an ML2 mechanism driver too - patches
          and/or advice welcome!

To set up a floating IP, you need the same pattern of Neutron data model
objects as you do for Neutron in general, which means:

- a tenant network, with an instance attached to it, that will be the target of
  the floating IP

- a Neutron router, with the tenant network connected to it

- a provider network with :code:`router:external True` that is set as the
  router's gateway (e.g. with :code:`neutron router-gateway-set`), and with a
  subnet with a CIDR that floating IPs will be allocated from

- a floating IP, allocated from the provider network subnet, that maps onto the
  instance attached to the tenant network.

Then the Calico agents will arrange that the floating IP is routed to the
instance's compute host, and then DNAT'd to the instance's fixed IP address.
