Calico with OpenStack
=====================

There are many ways to try out Calico with OpenStack, because OpenStack is a
sufficiently complex system that there is a small industry concerned with
deploying it correctly and successfully.

If you know nothing about OpenStack and just want to try out
Calico, you should consider the :doc:`opens-chef-install`
which can be used on Ubuntu 14.04 to set up a Calico OpenStack system.

Otherwise, if you already use OpenStack, you can install Calico by using

- the packaged install for Ubuntu 14.04 - see :doc:`ubuntu-opens-install`

- an RPM install for Red Hat Enterprise Linux 7 (RHEL 7 or 6.5) - see :doc:`redhat-opens-install`

- our experimental integration of Calico with Mirantis Fuel 5.1 - see :doc:`fuel-integration`.

In all cases, you just need at least two servers to get going (one OpenStack
controller and one OpenStack compute node).

.. toctree::
   :maxdepth: 1

   opens-chef-install
   redhat-opens-install
   ubuntu-opens-install
   fuel-integration
