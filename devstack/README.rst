==========================
DevStack plugin for Calico
==========================

Welcome to networking-calico's DevStack plugin!  The following instructions
explain how to set up a single or multiple node DevStack/Calico system, and
then how to see Calico connectivity in action.

.. note:: networking-calico includes a shell script that implements the
          following setup instructions, at
          https://git.openstack.org/cgit/openstack/networking-calico/tree/devstack/bootstrap.sh.
          You are welcome to use it, but we recommend that you read the
          following description first anyway, and briefly review the script's
          code, so that you will understand what the script does.


Single (or first) node setup
----------------------------

To prepare a single node DevStack/Calico system, that is with all controller
and compute functions running on the same node:

#. Download DevStack as usual.

#. Add to your DevStack local.conf file::

    enable_plugin calico https://git.openstack.org/openstack/networking-calico

#. Run ``stack.sh``

#. Create a shared, routed network with an IPv4 subnet::

    . openrc admin admin
    neutron net-create --shared --provider:network_type local calico
    neutron subnet-create --gateway 10.65.0.1 --enable-dhcp --ip-version 4 --name calico-v4 calico 10.65.0/24

#. Ensure that IPv4 and IPv6 forwarding are enabled::

    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1


Multi-node setup
----------------

This plugin also supports additional compute-only nodes.  So, in the system as
a whole, there can then be:

- one node with both controller and compute function

- any number of additional nodes with just compute function.

The first node should be prepared as described above.  Then, for each
additional compute node:

- set and export the SERVICE_HOST environment variable, to the name of the
  controller node; for example::

    export SERVICE_HOST=calico-vm18

- follow the steps above, except for the network and subnet creations, to
  install and set up DevStack with Calico on that node.


Demonstrating Calico connectivity
---------------------------------

Then, to see Calico connectivity in action:

#. Launch instances attached to the 'calico' network.

#. Use ``ip route`` to observe per-instance routes created by the Calico agent.

#. Log into each instance (e.g. through Horizon console) and verify that it can
   ping the others.
