---
title: Calico on OpenStack
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/openstack/installation/'
---

There are many ways to try out {{site.prodname}} with OpenStack, because OpenStack
is a sufficiently complex system that there is a small industry
concerned with deploying it correctly and successfully.

We provide instructions for the following methods:

- [Package-based install for Ubuntu]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/ubuntu)

- [RPM-based install for Red Hat Enterprise Linux (RHEL)]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/redhat)

- [DevStack]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/devstack) (for development purposes only—not recommended for production!)

In all cases, except DevStack, you will need at least two or three servers to
get going: one OpenStack controller and one or more OpenStack compute nodes.
