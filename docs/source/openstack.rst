.. # Copyright (c) Metaswitch Networks 2015. All rights reserved.
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

Calico with OpenStack
=====================

There are many ways to try out Calico with OpenStack, because OpenStack is a
sufficiently complex system that there is a small industry concerned with
deploying it correctly and successfully.

If you know nothing about OpenStack and just want to try out
Calico, you should consider the :doc:`opens-chef-install`
which can be used on Ubuntu 14.04 to set up a Calico OpenStack system.

Otherwise, if you already use OpenStack, you can install Calico via any of the
following methods:

- the packaged install for Ubuntu 14.04 - see :doc:`ubuntu-opens-install`

- an RPM install for Red Hat Enterprise Linux 7 (RHEL 7) - see
  :doc:`redhat-opens-install`

- our integration with Canonical's Juju Charms - see :doc:`juju-opens-install`

- our integration of Calico with Mirantis Fuel 6.1 - see :doc:`fuel-integration`

In all cases, you just need at least two servers to get going (one OpenStack
controller and one OpenStack compute node).

.. toctree::
   :maxdepth: 1

   opens-chef-install
   redhat-opens-install
   ubuntu-opens-install
   juju-opens-install
   opens-upgrade
   bird-rr-config
   fuel-integration
   worked-examples-openstack
