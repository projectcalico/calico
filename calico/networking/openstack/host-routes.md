---
title: Host routes
description: Options for host routing with Calico.
canonical_url: '/networking/openstack/host-routes'
---

Neutron allows "host routes" to be configured on a subnet, with each host route
comprising

- an IP destination prefix
- a next hop IP for routing to that prefix.

When an instance is launched and gets an IP from that subnet, Neutron arranges,
via DHCP, that the instance's routing table gets those routes.

With {{site.prodname}}, a host route's next hop IP should be the local host
----------------------------------------------------------------

networking-calico supports host routes, but it's important to note that a host
route is only consistent with {{site.prodname}} when its next hop IP represents the local
hypervisor.  This is because the local hypervisor, in a {{site.prodname}} setup, *always*
routes all data from an instance and so is always the next hop IP for data to
any destination.  If the instance's routing table has a route with some other
next hop IP, that next hop IP address will effectively be ignored, and the data
will likely *not* pass through the implied router; instead the data will go
first to the hypervisor, and then the hypervisor's routing table will determine
its next IP hop from there.

Specifically, each host route's next hop IP should be the gateway IP of the
subnet that the desired instance NIC is attached to, and from which it got its
IP address - where 'desired instance NIC' means the one that you want data for
that host route to go through.  In networking-calico's usage, subnet gateway
IPs represent the local hypervisor, because data sent by an instance is always
routed there.

> **Note**: networking-calico avoids unnecessary IP usage by using the subnet
> gateway IP to represent the local compute host, on every compute host where
> that subnet is being used. Although that might initially sound odd, it works
> because no data is ever sent to or from the gateway IP address; the gateway
> IP is only used as the next hop address for the first IP hop from an instance
> to its compute host, and then the compute host routes the data again,
> according to its routing table, to wherever it needs to go. This also means
> that the gateway IP address really is functioning as each instance's default
> gateway, in the generally understood sense.
>
{: .alert .alert-info}

When are host routes useful with {{site.prodname}}?
----------------------------------------

Host routes are useful with {{site.prodname}} when an instance has multiple NICs and you
want to specify which NIC should be used for data to particular prefixes.

When an instance has multiple NICs, it should have a default route through only
one of those NICs, and use non-default routes to direct appropriate traffic
through the other NICs.  Neutron host routes can be used to establish those
non-default routes; alternatively they can also be programmed manually in the
instance.

For example, suppose an instance has eth0 attached to a subnet with gateway
10.65.0.1, eth1 attached to a subnet with gateway 11.8.0.1, and a default route
via eth0.  Then a host route like

```bash
11.11.0.0/16,11.8.0.1
```
{: .no-select-button}

can be configured for the subnet, to say that data to 11.11.0.0/16 should go
out through eth1.  The instance's routing table will then be:

```bash
default via 10.65.0.1 dev eth0
10.65.0.0/24 dev eth0
11.8.0.0/24 dev eth1
11.11.0.0/16 via 11.8.0.1 dev eth1
```
{: .no-select-button}

When an instance only has a single network attachment, and so a single NIC,
host routes cannot make any difference to how data is routed, so it is
unhelpful (although also harmless) to configure them.  Regardless of what the
instance's routing table says, data must exit over the single NIC, and is
always layer-2-terminated and rerouted by the host according to the host's
routing table.  It's required for the host's routing table to cover whatever
destinations instances may want to send to, and host routes don't add anything
to that.
