Installing Calico and OpenStack
===============================

If you know nothing about OpenStack and just want to try out
Calico, you should consider the :doc:`opens-chef-install`
which can be used on Ubuntu 14.04 to set up a Calico OpenStack system.

Otherwise, if you already use OpenStack, you can install Calico by using 

- the packaged install for Ubuntu 14.04 - see :doc:`ubuntu-opens-install`
- an RPM install for Red Hat Enterprise Linux 7 (RHEL 7) - see :doc:`redhat-opens-install`.

All you need is at least two servers to get going (one OpenStack controller and one
OpenStack compute node).

.. _opens-install-inst-next-steps:

Next Steps
----------

Once you have installed Calico onto an OpenStack system, 
you may wish to review the Calico configuration files and
make adjustments (such as to the logging targets and levels). The
following article provides a reference to the available configuration
options.

-  :doc:`configuration`

Before you can use your new Calico install, you'll need to configure the
IP address ranges your VMs will use. This following article explains how
to do this (in particular :ref:`opens-external-conn-setup`).

-  :doc:`opens-external-conn`

Now you've installed and configured Calico you'll want to test that it
is functioning correctly. The following article describes how you can
verify that Calico is functioning.

-  :doc:`verification`

