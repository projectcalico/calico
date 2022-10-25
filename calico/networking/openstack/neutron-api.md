---
title: Calico's interpretation of Neutron API calls
description: Effects of the Neutron API calls on the network.
canonical_url: '/networking/openstack/neutron-api'
---

When running in an OpenStack deployment, {{site.prodname}} receives and interprets
certain Neutron API actions, in order to program those actions down into
the network. However, because {{site.prodname}} is substantially simpler than much
of what Neutron generally allows (see [IP addressing and connectivity]({{ site.baseurl }}/networking/openstack/connectivity)) and because it's a purely layer 3 model (see [The {{site.prodname}} data path]({{ site.baseurl }}/reference/architecture/data-path), not all Neutron API calls will have the same effect as they would with other backends.

This document will go into detail on the full range of Neutron API
calls, and will discuss the effect they have on the network. It uses the {% include open-new-window.html text='Networking API v2.0' url='http://developer.openstack.org/api-ref-networking-v2.html' %}
document from OpenStack as a basis for listing the various objects that
the Neutron API uses: see that document for more information about what
Neutron expects more generally.

Additionally, there is a [section of this document](#horizon) that briefly covers
Horizon actions.

## Networks

Networks are the basic networking concept in Neutron. A Neutron network
is considered to be roughly equivalent to a physical network in terms of
function: it defines a single layer 2 connectivity graph.

In vanilla Neutron, these can map to the underlay network in various
ways, either by being encapsulated over it or by being directly mapped
to it.

Generally speaking, Neutron networks can be created by all tenants. The
administrator tenant will generally create some public Neutron networks
that map to the underlay physical network directly for providing
floating IPs: other tenants will create their own private Neutron
networks as necessary.

In {{site.prodname}}, because all traffic is L3 and routed, the role of Neutron
network as L2 connectivity domain is not helpful. Therefore, in {{site.prodname}},
Neutron networks are simply containers for subnets. Best practices for
operators configuring Neutron networks in {{site.prodname}} deployments can be
found in [Set up OpenStack]({{ site.baseurl }}/networking/openstack/connectivity#opens-external-conn-setup).

It is not useful for non-administrator tenants to create their own
Neutron networks. Although {{site.prodname}} will allow non-administrator tenants
to create Neutron networks, generally speaking administrators should use
Neutron quotas to prevent non-administrator tenants from doing this.

Network creation events on the API are no-op events in {{site.prodname}}: a
positive (2XX) response will be sent but no programming will actually
occur.

Extended Attributes: Provider Networks
--------------------------------------

Neutron Provider networks are not used in {{site.prodname}} deployments. Setting
provider network extended attributes will have no effect. See
[IP addressing and connectivity]({{ site.baseurl }}/networking/openstack/connectivity) to understand why Neutron provider networks are not
needed.

## Subnets

Neutron subnets are child objects of Neutron networks. In vanilla
Neutron, a subnet is a collection of IP addresses and other network
configuration (e.g. DNS servers) that is associated with a single
Neutron network. A single Neutron network may have multiple Neutron
subnets associated with it. Each Neutron subnet represents either an
IPv4 or IPv6 block of addresses.

Best practices for configuring Neutron subnets in {{site.prodname}} deployments can
be found in [Set up OpenStack]({{ site.baseurl }}/networking/openstack/connectivity#opens-external-conn-setup).

In {{site.prodname}}, these roles for the Neutron subnet are preserved in their
entirety. All properties associated with these Neutron subnets are
preserved and remain meaningful except for:

`host_routes`

:   These have no effect, as the compute nodes will route traffic
    immediately after it egresses the VM.

## Ports

In vanilla Neutron, a port represents a connection from a VM to a single
layer 2 Neutron network. Obviously, the meaning of this object changes
in a {{site.prodname}} deployment: instead, a port is a connection from a VM to the
shared layer 3 network that {{site.prodname}} builds in Neutron.

All properties on a port work as normal, except for the following:

`network_id`

:   The network ID still controls which Neutron network the port is
    attached to, and therefore still controls which Neutron subnets it
    will be placed in. However, as per the [note above](#networks),
    the Neutron network that a port is placed in does not affect which
    machines in the deployment it can contact.

### Extended Attributes: Port Binding Attributes

The `binding:host-id` attribute works as normal. The following notes
apply to the other attributes:

`binding:profile`

:   This is unused in {{site.prodname}}.

`binding:vnic_type`

:   This field, if used, **must** be set to `normal`. If set to any
    other value, {{site.prodname}} will not correctly function!

## Quotas

Neutron quotas function unchanged.

In most deployments we recommend setting non-administrator tenant quotas
for almost all Neutron objects to zero. For more information, see [Set up OpenStack]({{ site.baseurl }}/networking/openstack/connectivity#opens-external-conn-setup).

## Security Groups

Security groups in vanilla OpenStack provide packet filtering processing
to individual ports. They can be used to limit the traffic a port may
issue.

In {{site.prodname}}, security groups have all the same function. Additionally,
they serve to provide the connectivity-limiting function that in vanilla
OpenStack is provided by Neutron networks.

All the attributes of security groups remain unchanged in {{site.prodname}}.

{: id="routers"}

## Floating IPs

Floating IPs are supported at beta level. For more information, see [Floating IPs](floating-ips).

## Neutron Routers

Calico provides connectivity by default between all Neutron networks,
regardless of whether there are Router objects between them in the Neutron data
model.  See [Detailed semantics](semantics) for a
fuller explanation.  Where isolation of a particular Neutron network is
desired, we recommend expressing that through security group rules.

## Load Balancer as a Service

Load Balancer as a Service (LBaaS) does not function in a {{site.prodname}} network. Any
attempt to create one will fail.

> **Note**: It is possible that in a future version of {{site.prodname}} LBaaS may be
> functional. Watch this space.
{: .alert .alert-info}

## Horizon

Horizon makes many provisioning actions available that mirror options on
the Neutron API. This section lists them, and indicates whether they can
be used or not, and any subtleties that might be present in them.

Much of the detail has been left out of this section, and is instead
present in the relevant Neutron API sections above: please consult them
for more.

### Section: Project

#### Tab: Compute -&gt; Instances

When launching instances, remember that security groups are used to
determine reachability, not networks. Choose networks based on whether
you need an external or an internal IP address, and choose security
groups based on the machines you'd like to talk to in the cloud. See
[IP addressing and connectivity](connectivity) for more.

#### Tab: Compute -&gt; Access & Security

As noted above, tenants should ensure they configure their security
groups to set up their connectivity appropriately.

#### Tab: Network -&gt; Network Topology

For the 'Create Network' button, see the [Networks](#networks) section.
For the 'Create Router' button, see the [Layer 3 Routing](#routers) section.

#### Tab: Network -&gt; Networks

For networks and subnets, see the sections on [Networks](#networks) and
[Subnets](#subnets).

#### Tab: Network -&gt; Routers

Tenants should be prevented from creating routers, as they serve no
purpose in a {{site.prodname}} network. See [Layer 3 Routing](#routers) for more.

### Section: Admin

#### Tab: System Panel -&gt; Networks

In the course of general operation administrators are not expected to
make changes to their networking configuration. However, for initial
network setup, this panel may be used to make changes. See
[IP addressing and connectivity](connectivity) for details on how to achieve this setup.

#### Tab: System Panel -&gt; Routers

Administrators should not create routers, as they serve no purpose in a
{{site.prodname}} network. See [Layer 3 Routing](#routers) for more.
