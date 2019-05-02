---
title: System requirements
redirect_from: latest/getting-started/openstack/requirements
canonical_url: 'https://docs.projectcalico.org/v3.7/getting-started/openstack/requirements'
---

{% include {{page.version}}/reqs-sys.md orch="OpenStack" %}

## OpenStack requirements

We aim to develop and maintain the Neutron driver for {{site.prodname}}
(networking-calico) so that its master code works with OpenStack master or any
previous release (back to Icehouse), on any operating system, independently of
the deployment mechanism that is used to install it.

However, we recommend using OpenStack Newton or later, and our active support
and testing of {{site.prodname}} {{page.version}} with OpenStack is limited to
the following versions:

- Ocata
- Pike

{% include {{page.version}}/reqs-kernel.md %}

## Nova patch needed with Mitaka and earlier

With OpenStack Mitaka and earlier, and if your libvirt is >= 1.3.3 and < 3.1,
you will need to patch the Nova code post installation, on each compute host,
as in [this change](https://review.openstack.org/#/c/411936/).  In case you
need the same Nova code to work with all possible libvirt versions, you should
then add [this further change](https://review.openstack.org/#/c/448203/).
OpenStack Newton and later already include these two changes.
