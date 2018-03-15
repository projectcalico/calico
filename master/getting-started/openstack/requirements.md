---
title: System requirements
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/openstack/requirements'
---

{% include {{page.version}}/reqs-sys.md orch="OpenStack" %}

## OpenStack requirements

We aim to develop and maintain the Neutron driver for {{site.prodname}}
(networking-calico) so that its master code works with OpenStack master or any
previous release (back to Icehouse), on any operating system, independently of
the deployment mechanism that is used to install it.

However, our active support and testing of {{site.prodname}} {{page.version}} 
with OpenStack is limited to the following versions:

- Ocata
- Pike

{% include {{page.version}}/reqs-kernel.md %}