---
title: Juju Install
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/openstack/installation/juju'
---

You can use Ubuntu's [Juju Charms](https://jujucharms.com/) to quickly deploy a
Calico/OpenStack cluster.  All you need to do is download one of our bundles,
then deploy it to your Juju environment using [any of the standard
methods](https://docs.jujucharms.com/2.3/en/charms-bundles). This will get you a
simple OpenStack deployment with two compute nodes, which you can then easily
scale out by adding more instances of the `nova-compute` charm.

## Bundles

For Calico with Mitaka:
<https://jujucharms.com/u/project-calico/calico-mitaka-juju2>

For Calico with Liberty and earlier we don't have bundles published in the
charm store, but you can generate a bundle from our repo at
<https://github.com/projectcalico/bundle-openstack-calico>.  In particular
please see
<https://github.com/projectcalico/bundle-openstack-calico/blob/master/icehouse-kilo-liberty/README.rst>.

The default admin password for these deployments is "openstack" - you may wish
to update this in the bundle (search for the keystone "admin-password" option).

For more detailed information, please see [this blog
post](https://www.projectcalico.org/exploring-juju/) on the Calico blog.
