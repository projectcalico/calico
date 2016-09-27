---
title: Juju Install
---

If you're in a position to use Ubuntu's [Juju Charms](https://jujucharms.com/) deployment tool, you can quickly get a
Calico-based OpenStack deployment up and running. All you need to do is
download one of our bundles, and then deploy it to your Juju environment
using [any of the standard methods](https://jujucharms.com/1.20/charms-bundles). This will get
you a simple OpenStack deployment with two compute nodes, which you can
then easily scale out by adding more instances of the `nova-compute`
charm.

Bundles
=======

Icehouse:
<https://raw.githubusercontent.com/projectcalico/calico/master/source/_static/juju/icehouse.yaml>

Juno:
<https://raw.githubusercontent.com/projectcalico/calico/master/source/_static/juju/juno.yaml>

Kilo:
<https://raw.githubusercontent.com/projectcalico/calico/master/source/_static/juju/kilo.yaml>

The default admin password for the deployment is "openstack" - you may
wish to update this in the bundle (search for the keystone
"admin-password" option).

For more detailed information, please see [this blog
post](http://www.projectcalico.org/exploring-juju/) on the Calico blog.
