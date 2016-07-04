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

Juju Install
============

If you're in a position to use Ubuntu's `Juju Charms`_ deployment tool, you can
quickly get a Calico-based OpenStack deployment up and running. All you need
to do is download one of our bundles, and then deploy it to your Juju
environment using `any of the standard methods`_. This will get you a simple
OpenStack deployment with two compute nodes, which you can then easily scale
out by adding more instances of the ``nova-compute`` charm.

Bundles
-------

Icehouse: https://raw.githubusercontent.com/projectcalico/calico/master/docs/source/_static/juju/icehouse.yaml
Juno: https://raw.githubusercontent.com/projectcalico/calico/master/docs/source/_static/juju/juno.yaml
Kilo: https://raw.githubusercontent.com/projectcalico/calico/master/docs/source/_static/juju/kilo.yaml

The default admin password for the deployment is "openstack" - you may wish to
update this in the bundle (search for the keystone "admin-password" option).

For more detailed information, please see `this blog post`_ on the Calico blog.

.. _Juju Charms: https://jujucharms.com/
.. _any of the standard methods: https://jujucharms.com/docs/1.20/charms-bundles
.. _this blog post: http://www.projectcalico.org/exploring-juju/
