.. # Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

.. _opens-install-inst-next-steps:

Next Steps
==========

Once you have installed Calico onto an OpenStack system,
you may wish to review the Calico configuration files and
make adjustments (such as to the logging targets and levels). The
following article provides a reference to the available configuration
options.

.. toctree::
   :maxdepth: 2

   configuration

If you're going to run Calico in production, you should also review the
guide to securing Calico:

.. toctree::
   :maxdepth: 2

   securing-calico

Before you can use your new Calico install, you'll need to configure the
IP address ranges your VMs will use. This following article explains how
to do this (in particular :ref:`opens-external-conn-setup`).

.. toctree::
   :maxdepth: 2

   opens-external-conn

Now you've installed and configured Calico you'll want to test that it
is functioning correctly. The following article describes how you can
verify that Calico is functioning.

.. toctree::
   :maxdepth: 2

   verification

If you would like your workloads to have IPv6 connectivity as well as or
instead of IPv4, the following page explains how to do that.

.. toctree::
   :maxdepth: 2

   ipv6

To update your Calico installation, please consult the following page for
instructions on how to do so.

.. toctree::
   :maxdepth: 2

   opens-upgrade
