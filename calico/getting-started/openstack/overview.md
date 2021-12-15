---
title: Calico for OpenStack
description: Review the Calico components used in an OpenStack deployment.
canonical_url: '/getting-started/openstack/index'
---

{{site.prodname}}'s integration with OpenStack consists of the following pieces.

- etcd, providing a distributed key/value database that is accessible from all
  compute hosts and Neutron servers.

- Felix (the {{site.prodname}} agent) running on each compute host.  Felix reads
  information from etcd that specifies workloads and their properties (IP
  addresses, security etc.), and implements that connectivity and security for
  them.  Felix also reports its own agent status, and the programming status
  for each workload, through etcd.

- BIRD, also running on each compute host, to propagate local workload routes
  to other compute hosts and infrastructure routers.

- The {{site.prodname}} driver for Neutron, that runs as part of the Neutron server on
  each machine where the Neutron server runs.  (There can be just one Neutron
  server, but typically there are more, to provide higher availability.)  This
  driver handles OpenStack network, subnet, instance and security operations
  and translates them into equivalent etcd data for Felix to implement.  It
  also reads the agent and per-port status information that Felix writes into
  etcd, and reports this into the Neutron DB.

- The {{site.prodname}} DHCP agent, running on each compute host, that configures and
  launches Dnsmasq instances to provide DHCP for the locally hosted workloads.
  Architecturally this fills the same role as the reference Neutron DHCP agent;
  the key difference is that it gets its information from Etcd instead of by
  RPC from the Neutron server, as we have found this to be more scalable.

The Etcd, Felix and BIRD pieces are the same as in other {{site.prodname}} integrations,
and so independent of OpenStack.  The {{site.prodname}} Neutron driver and DHCP agent are
specific to OpenStack, and are provided by the {% include open-new-window.html text='networking-calico' url='https://github.com/projectcalico/networking-calico/' %} project.

From an OpenStack point of view, networking-calico is just one of many possible
Neutron drivers that provide connectivity between instances (VMs) as specified
by the Neutron API. Refer to [{{site.prodname}}'s interpretation of Neutron API calls](../../networking/openstack/neutron-api) for more detail about the
parts of the Neutron API that the networking-calico provides.
