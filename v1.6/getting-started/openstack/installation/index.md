---
title: Calico with OpenStack
---

There are many ways to try out Calico with OpenStack, because OpenStack
is a sufficiently complex system that there is a small industry
concerned with deploying it correctly and successfully.

You can install Calico via any of the following methods:

-   packaged install for Ubuntu 14.04 (Trusty) or 16.04 (Xenial) - see [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/ubuntu).
-   an RPM install for Red Hat Enterprise Linux 7 (RHEL 7) - see [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/redhat).
-   Canonical's Juju Charms - see
    [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/juju).
-   Mirantis Fuel - see
    [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/fuel).

The [Chef
installation]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/chef),
which we used to recommend, is now very old and only supports Icehouse. We now
recommend using one of the above methods instead.

In all cases, you will need at least two or three servers to get going: one
OpenStack controller, one OpenStack compute node and, for Mirantis Fuel, a
third node to serve as the Fuel master.
