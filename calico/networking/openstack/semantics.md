---
title: Detailed semantics
description: Calico provides connectivity that is different from traditional Neutron API semantics.
canonical_url: '/networking/openstack/semantics'
---

A {{site.prodname}} network is a Neutron network (either provider or tenant) whose
connectivity is implemented, on every compute host with instances attached to
that network, by the `calico` plugin or ML2 mechanism driver.  There can be
just one {{site.prodname}} network, or any number of them.  This page describes the
connectivity that {{site.prodname}} provides between instances attached to the same
network, and between instances attached to different {{site.prodname}} networks, and
between instances and the Internet; and explains how and why this connectivity
is in some details different from traditional Neutron API semantics.

## Connectivity between instances on the same network

{{site.prodname}} provides IP connectivity, but not layer 2 (L2) adjacency, between
instances attached to the same {{site.prodname}} network.  This means that:

- An instance can ping the IP of another instance, and make other IP-based
  connections to other instances.  (Unless restricted by security group
  configuration.)

- If an instances probe the IP path to another instance, it will find that
  there are intermediate IP hops in the path; or in other words, that the
  instances are not directly connected.

- Applications or protocols that actually require L2 adjacency - such as
  routing protocols like OSPF - will not run successfully on instances on a
  {{site.prodname}} network.  But the vast majority of applications that are IP-based will
  be just fine.

Traditionally, a Neutron network has always provided L2 adjacency between its
instances, so this is the first way that C{{site.prodname}} differs from traditional
Neutron semantics.  Up to and including the Mitaka release, L2 adjacency was an
assumed property of a Neutron network; so deployments using {{site.prodname}} simply had
to *understand* that {{site.prodname}} networks were different in this detail.

As of the Newton release, {{site.prodname}}'s IP-only connectivity is expressible in the
Neutron API, as a Network whose `l2_adjacency` property is `False`.
However work is still needed to make {{site.prodname}} networks report `l2_adjacency
False`, so at the moment - unfortunately - it *still* has to be understood that
{{site.prodname}} networks do not provide L2 adjacency, even though they report
`l2_adjacency True` when queried on the API.

> **Note**: {{site.prodname}}'s connectivity design, based on IP routing, allows unicast IP
> and anycast IP. Anycast IP also requires support for allowed-address-pairs,
> or some other way of assigning the same IP address to more than one instance;
> work for allowed-address-pairs support is in progress at {% include open-new-window.html text='opendev' url='https://review.openstack.org/#/c/344008/' %}.
> Multicast IP support is on our roadmap but not yet implemented. Broadcast IP
> is not possible because it depends on L2 adjacency.
{: .alert .alert-info}

## Connectivity between different {{site.prodname}} networks

{{site.prodname}} provides *exactly* the same connectivity between instances on different
{{site.prodname}} networks, as it does between instances on the same {{site.prodname}} network.

It is important to note that this is equally true for 'provider' and 'tenant'
{{site.prodname}} networks (i.e. for networks that are provisioned by the cloud operator,
or by a particular tenant or project), and for connectivity between any mix of
those networks.  There is no way, with {{site.prodname}}, to get a tenant network that is
isolated by default at the connectivity level, per standard Neutron API
semantics for a tenant network that is not connected to a router, even if the
{{site.prodname}} tenant network is *not* connected to a Neutron router, or if there are
no Neutron routers in the deployment at all.

{{site.prodname}} works this way because it targets use cases where instances are attached
either to provider networks directly, or (in Neutron data model terms) to
tenant networks that *are* attached through a router to a provider network.
One reason for the latter case is to use floating IPs with {{site.prodname}}, because in
current Neutron the target of a floating IP has to be an instance attached to a
tenant network.  For more on this, see [Floating IPs](floating-ips).

## Flat IP addressing

An implication of that connectivity between networks is that {{site.prodname}} assumes
that the IP addresses it handles are all in a single, flat address space.  For
example, if one network has a subnet with CIDR 10.65.0.0/24, and another
network has a subnet with CIDR 172.18.0.0/16, an instance with IP 10.65.0.2 can
directly address an instance on the other network with IP 172.18.3.23, and the
IP packet will travel all the way between them with source IP 10.65.0.2 and
destination IP 172.18.3.23.  There is no NAT anywhere along this datapath.

## Evaluation against Neutron semantics

{{site.prodname}} targets use cases that correspond to two Neutron data model patterns.

Firstly, where instances are attached directly to provider networks:

![]({{site.baseurl}}/images/networking-calico/calico-provider.png)

Secondly, where instances are attached to an externally-connected tenant
network:

![]({{site.baseurl}}/images/networking-calico/calico-tenant.png)

In the general case those patterns may be combined - so in general there may be
any number of {{site.prodname}} provider networks, and any number of {{site.prodname}} tenant
networks, so long as each of the tenant networks is connected through some
router to a provider network.  The purpose of using tenant networks - instead
of always using provider networks - is only so as to enable floating IPs.  The
purpose of provisioning multiple networks of either kind - instead of just
one - is typically to allow the user to control what kind of fixed IP an
instance gets.

However many {{site.prodname}} networks there are, all their IP addresses (in associated
Neutron subnet or subnet pool objects) must be defined or understood as
belonging to a single, flat address space.

Finally it must be understood that there is no L2 adjacency between any
instances, even those that are attached to the same network.  In a future
OpenStack release, we hope to make this explicit, by arranging for {{site.prodname}}
networks to report `l2_adjacency False`.

Subject to those restrictions and understandings, we believe that
networking-calico fully implements Neutron semantics, i.e. that it provides the
connectivity that an operator would expect for a given sequence of Neutron API
setup calls.
