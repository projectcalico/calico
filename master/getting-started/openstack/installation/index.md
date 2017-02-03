---
title: Calico with OpenStack
---

There are many ways to try out Calico with OpenStack, because OpenStack
is a sufficiently complex system that there is a small industry
concerned with deploying it correctly and successfully.

You can install Calico via any of the following methods:

- [Package-based install for Ubuntu 14.04 (Trusty) or 16.04
  (Xenial)]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/ubuntu)

- [RPM-based install for Red Hat Enterprise Linux 7 (RHEL
  7)]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/redhat)


- [Canonical's Juju
  Charms]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/juju)

- [Mirantis
  Fuel]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/fuel)

- [DevStack]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/devstack)

The [Chef
installation]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/chef),
which we used to recommend, is now very old and only supports Icehouse. We now
recommend using one of the above methods instead.

In all cases, except DevStack, you will need at least two or three servers to
get going: one OpenStack controller, one OpenStack compute node and, for
Mirantis Fuel, a third node to serve as the Fuel master.
