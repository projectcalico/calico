---
title: Kuryr
description: Use Kuryr with Calico networking.
canonical_url: '/networking/openstack/kuryr'
---

networking-calico works with Kuryr; this means using Neutron, with the {{site.prodname}}
ML2 driver, to provide networking for container workloads.

You can use DevStack to install a single node {{site.prodname}}/Kuryr system, with a
`local.conf` file like this:

    [[local|localrc]]
    ADMIN_PASSWORD=015133ea2bdc46ed434c
    DATABASE_PASSWORD=d0060b07d3f3631ece78
    RABBIT_PASSWORD=6366743536a8216bde26
    SERVICE_PASSWORD=91eb72bcafb4ddf246ab
    SERVICE_TOKEN=c5680feca5e2c9c8f820

    enable_plugin networking-calico git://git.openstack.org/openstack/networking-calico
    enable_plugin kuryr git://git.openstack.org/openstack/kuryr
    enable_service kuryr
    enable_service etcd-server
    enable_service docker-engine

    LOGFILE=stack.log
    LOG_COLOR=False

Please follow general Kuryr instructions for creating a Docker network that
uses Kuryr as its backend, and for launching containers on that network.  Then
if you look at the IP routing table and iptables, you will see {{site.prodname}} routes to
the containers.

{{site.prodname}} for containers without Kuryr
-----------------------------------

The {{site.prodname}} project also provides networking for containers more directly,
without Neutron and Kuryr as intermediaries.  Please see [Getting
Started]({{ site.baseurl }}/getting-started) for details.
