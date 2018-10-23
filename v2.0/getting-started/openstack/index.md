---
title: Calico for OpenStack
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/openstack/'
---

Calico's integration with OpenStack consists of the following pieces.

- Etcd, providing a distributed key/value database that is accessible from all
  compute hosts and Neutron servers.

- Felix (the Calico agent) running on each compute host.  Felix reads
  information from Etcd that specifies workloads and their properties (IP
  addresses, security etc.), and implements that connectivity and security for
  them.  Felix also reports its own agent status, and the programming status
  for each workload, through Etcd.

- BIRD, also running on each compute host, to propagate local workload routes
  to other compute hosts and infrastructure routers.

- The Calico driver for Neutron, that runs as part of the Neutron server on
  each machine where the Neutron server runs.  (There can be just one Neutron
  server, but typically there are more, to provide higher availability.)  This
  driver handles OpenStack network, subnet, instance and security operations
  and translates them into equivalent Etcd data for Felix to implement.  It
  also reads the agent and per-port status information that Felix writes into
  Etcd, and reports this into the Neutron DB.

- The Calico DHCP agent, running on each compute host, that configures and
  launches Dnsmasq instances to provide DHCP for the locally hosted workloads.
  Architecturally this fills the same role as the reference Neutron DHCP agent;
  the key difference is that it gets its information from Etcd instead of by
  RPC from the Neutron server, as we have found this to be more scalable.

The Etcd, Felix and BIRD pieces are the same as in other Calico integrations,
and so independent of OpenStack.  The Calico Neutron driver and DHCP agent are
specific to OpenStack, and are provided by the
[networking-calico](http://git.openstack.org/cgit/openstack/networking-calico/)
project.  networking-calico is a Neutron stadium project.

From an OpenStack point of view, networking-calico is just one of many possible
Neutron drivers that provide connectivity between instances (VMs) as specified
by the Neutron API.  However there are some parts of the Neutron API that
networking-calico interprets differently, or does not implement at all.
Documentation for readers who are already familiar with OpenStack and Neutron,
and hence mostly interested in what is special or different about the
networking-calico driver, can be found at
[http://docs.openstack.org/developer/networking-calico/](http://docs.openstack.org/developer/networking-calico/).

The documentation here covers some of the ways of installing Calico in an
OpenStack deployment, plus introductory information on how to see that Calico
is working in your cluster.
