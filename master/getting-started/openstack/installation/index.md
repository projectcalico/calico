---
title: Calico with OpenStack
---

There are many ways to try out Calico with OpenStack, because OpenStack
is a sufficiently complex system that there is a small industry
concerned with deploying it correctly and successfully.

You can install Calico via any of the following methods:

-   the packaged install for Ubuntu 14.04 - see [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/ubuntu).
-   an RPM install for Red Hat Enterprise Linux 7 (RHEL 7) - see [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/redhat).
-   our integration of Calico with Mirantis Fuel 6.1 or 7.0 - see
    [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/fuel).
-   our integration with Canonical's Juju Charms - see
    [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/juju).

> **WARNING**
>
> The opens-chef-install, which we used to recommend,
> is now very old and it only supports Icehouse. For now, we
> recommend using one of the above integrations.
>

In all cases, you just need at least two to three servers to get going
(one OpenStack controller, one OpenStack compute node and, for Mirantis
Fuel, a third node to serve as the Fuel master).
