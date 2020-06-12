---
title: System requirements
description: Requirements for installing Calico on OpenStack nodes.
canonical_url: '/getting-started/openstack/requirements'
---

{% include content/reqs-sys.md orch="OpenStack" %}

## OpenStack requirements

The Calico Neutron driver is written in Python 3 and so requires an OpenStack release that
runs with Python 3.  Subject to that, we aim to develop and maintain the Neutron driver
for {{site.prodname}} (networking-calico) so that its master code works with OpenStack
master or any previous Python 3 release, on any operating system, independently of the
deployment mechanism that is used to install it.

However, we recommend using OpenStack Ussuri or later, and our active support and testing
of {{site.prodname}} {{page.version}} with OpenStack is with Ussuri.

{% include content/reqs-kernel.md %}
