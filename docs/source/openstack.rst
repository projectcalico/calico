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

Calico with OpenStack
=====================

There are many ways to try out Calico with OpenStack, because OpenStack is a
sufficiently complex system that there is a small industry concerned with
deploying it correctly and successfully.

You can install Calico via any of the following methods:

- the packaged install for Ubuntu 14.04 - see :doc:`ubuntu-opens-install`

- an RPM install for Red Hat Enterprise Linux 7 (RHEL 7) - see
  :doc:`redhat-opens-install`

- our integration of Calico with Mirantis Fuel 6.1 or 7.0 - see
  :doc:`fuel-integration`

- our integration with Canonical's Juju Charms - see :doc:`juju-opens-install`

.. warning:: The :doc:`opens-chef-install`, which we used to recommend,
             is now very old and it only supports Icehouse. For now, we
             recommend using one of the above integrations.

In all cases, you just need at least two to three servers to get going (one OpenStack
controller, one OpenStack compute node and, for Mirantis Fuel, a third node to
serve as the Fuel master).

.. toctree::b
   :maxdepth: 1

   ubuntu-opens-install
   redhat-opens-install
   fuel-integration
   juju-opens-install
   opens-chef-install
   opens-upgrade
   bird-rr-config
   worked-examples-openstack
