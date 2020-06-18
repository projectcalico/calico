---
title: System requirements
description: Requirements for installing Calico on OpenStack nodes.
canonical_url: '/getting-started/openstack/requirements'
---

{% include content/reqs-sys.md orch="OpenStack" %}

## OpenStack requirements

We aim to develop and maintain the Neutron driver for {{site.prodname}}
(networking-calico) so that its master code works with OpenStack master or any
previous release (back to Liberty), on any operating system, independently of
the deployment mechanism that is used to install it.  However, we recommend
using OpenStack Newton or later.

## Specific platform notes

### Active testing

Our active testing of {{site.prodname}} {{page.version}} with OpenStack is
with the following releases and platforms:

| Python version | OpenStack release | OS platform  |
|----------------|-------------------|--------------|
| Python 2       | Queens            | Ubuntu 18.04 |
| Python 2       | Rocky             | CentOS 7     |
| Python 3       | Ussuri            | Ubuntu 18.04 |

### Live migration with Train and later

Live migration with Train and later OpenStack releases requires
[`live_migration_wait_for_vif_plug`](https://docs.openstack.org/nova/ussuri//configuration/config.html)
to be set to false in `nova.conf`, on all compute nodes.

### Nova patch needed with Mitaka and earlier

With OpenStack Mitaka and earlier, and if your libvirt is >= 1.3.3 and < 3.1,
you will need to patch the Nova code post installation, on each compute host,
as in {% include open-new-window.html text='this change' url='https://review.openstack.org/#/c/411936/' %}.  In case you
need the same Nova code to work with all possible libvirt versions, you should
then add {% include open-new-window.html text='this further change' url='https://review.openstack.org/#/c/448203/' %}.
OpenStack Newton and later already include these two changes.

{% include content/reqs-kernel.md %}
