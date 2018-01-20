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

## Target platforms and OpenStack releases

We aim to develop and maintain the Neutron driver for Calico
(networking-calico) so that its master code works with OpenStack master or any
previous release (back to Icehouse), on any OS platform, and independently of
the deployment mechanism that is used to install it.

That said, we recommend using OpenStack Liberty or later, on Ubuntu Trusty or
Xenial, or RHEL/CentOS 7, as those are the platform combinations that are used
in most of our own testing, and by many third party Calico users.

## Nova patch needed with Mitaka and earlier

With OpenStack Mitaka and earlier, and if your libvirt is >= 1.3.3 and < 3.1,
you will need to patch the Nova code post installation, on each compute host,
as in [this change](https://review.openstack.org/#/c/411936/).  In case you
need the same Nova code to work with all possible libvirt versions, you should
then add [this further change](https://review.openstack.org/#/c/448203/).
OpenStack Newton and later already include these two changes.
