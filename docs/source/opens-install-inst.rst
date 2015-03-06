Installation Instructions
=========================

| These pages will guide you through installing Calico on your OpenStack
| nodes. If you know nothing about OpenStack and just want to try out
| Calico, you should consider the :doc:`opens-chef-install`
| for Ubuntu 14.04. Otherwise, we support \* packaged install for Ubuntu
| 14.04 - jump straight to :doc:`ubuntu-opens-install` to get started.

| \* RPM install for Red Hat Enterprise Linux (RHEL 7) - see
| :doc:`redhat-opens-install`.

All you need is at least two servers to get going.

.. _opens-install-inst-next-steps:

Next Steps
----------

At this point you may wish to review the Calico configuration files and
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

