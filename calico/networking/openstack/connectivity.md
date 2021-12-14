---
title: IP addressing and connectivity
description: Configure OpenStack networking for Calico.
canonical_url: '/networking/openstack/connectivity'
---

An OpenStack deployment is of limited use if its VMs cannot reach and be
reached by the outside world. This document will explain how to
configure your {{site.prodname}}-based OpenStack deployment to ensure that you have
the desired connectivity with the outside world.

## Major differences from standard OpenStack

If you've deployed OpenStack before you'll be thinking in terms of
routers, floating IPs, and external networks. {{site.prodname}}'s focus on
simplicity means that it doesn't use any of these concepts. This section
is mostly a warning: even if you think you know what you're doing,
please read the rest of this article. You might be surprised!

## Setting up connectivity

### Part 0: Deciding your address ranges

For {{site.prodname}}, it's best to pick up to three address ranges you're going to
use from the following three options. If it's possible, use all three.

The first option is an IPv6 address range, assuming you want your VMs to
have IPv6 connectivity. Note that you can only use this range if your
data center network can route IPv6 traffic. All IPv6 addresses should be
considered 'externally reachable', so this needs to be a range that will
be routed to your gateway router: ideally globally scoped.

The second option is a 'private' IPv4 range, assuming you want your VMs
to have IPv4 connectivity. This is the most likely range for you to
configure. This range will contain all VMs that cannot be reached by
traffic that originates from outside the data center.

The third option is a 'public' IPv4 range, assuming you want your VMs to
have IPv4 connectivity. This range will contain all the VMs that want to
be reachable by traffic that originates from outside the data center.
Make sure that traffic destined for this range from outside the data
center will be routed to your gateway, or nothing will work!

The minimum requirement is one of those address ranges.

### Part 1: Configuring the fabric

Your {{site.prodname}} deployment will require a gateway router. In most
non-trivial cases this will be a heavy-duty router, but if you're
deploying a smaller network (maybe for testing purposes) and don't have
access to one you can use a Linux server in the role.

The gateway router needs to be on the default route for all of your
compute hosts. This is to ensure that all traffic destined to leave the
data center goes via the gateway. That means that in a flat L3 topology
the gateway router needs to be set as the next hop. In a more complex
setup such as a multi-tier L3 topology the next hop may need to be
slightly shorter, for example to a top-of-rack router, which will in
turn need to route towards the gateway router.

Then, the gateway router needs to be a BGP peer of the {{site.prodname}} network.
This could be a peer of one or more route reflectors, or in smaller
topologies directly peering with the compute hosts. This is to ensure it
knows the routes to all the VMs, so that it knows which way to route
traffic destined for them. Instructions for configuring your gateway
(and potentially BGP route reflectors) are beyond the scope of this
document. If you don't know how to do this or want to know how {{site.prodname}}
fits into your existing deployment, please get in touch on our mailing
list: it is difficult to add a generic solution to this problem to this
article.

If your gateway uses eBGP to advertise routes externally, you'll need to
configure the BGP policy on the gateway to ensure that it does not
export routes to the private IPv4 address range you configured above.
Otherwise, in smaller deployments, you just need to make sure that
external traffic destined for your VMs will get routed to the gateway.
How you do this is outside the scope of this document: please ask for
assistance on our mailing list.

Finally, configure your gateway to do stateful PNAT for any traffic
coming from the IPv4 internal range. This ensures that even VMs that
cannot be directly reached from the external network can still contact
servers themselves, in order to do things like request software updates.
Again, the actual manner in which this is configured depends on your
router.

{: id="opens-external-conn-setup"}

### Part 2: Set up OpenStack

In OpenStack, you want to set up two shared Neutron networks. For the
first, add one IPv4 subnet containing the 'external' IPv4 range. Make
sure the subnet has a gateway IP, and that DHCP is enabled.
Additionally, add one IPv6 subnet containing half your IPv6 range, again
with a gateway IP and DHCP enabled. Make sure this network has a name
that makes it clear that it's for your 'externally accessible' VMs.
Maybe even mark it an 'external' network, though that has no effect on
what {{site.prodname}} does.

For the second network, add one IPv4 subnet containing the 'private'
IPv4 range and one IPv6 subnet containing the other half of your IPv6
range, both with gateway IPs and DHCP enabled. Make sure this network
has a name that makes it clear that it's for your 'private' VMs. Note
that if you give this network part of your IPv6 range these VMs will all
be reachable over IPv6. It is expected that all users will want to
deploy in this way, but if you don't, either don't give these VMs IPv6
addresses or give them private ones that are not advertised by your
gateway.

Then, configure the default network, subnet, router and floating IP
quota for all tenants to be 0 to prevent them from creating more
networks and confusing themselves!

A sample configuration is below, showing the networks and two of the
four subnets (as they differ only in their address ranges, all other
configuration is the same).

From the controller, issue the following Neutron CLI command.

```bash
neutron net-list
```
It returns a list of the networks.

```  
+--------------------------------------+----------+----------------------------------------------------------+
| id                                   | name     | subnets                                                  |
+--------------------------------------+----------+----------------------------------------------------------+
| 8d5dec25-a6aa-4e18-8706-a51637a428c2 | external | 54db559c-5e1d-4bdc-83b0-c479ef2a0ead 172.18.208.0/24     |
|                                      |          | cf6ceea0-dde0-4018-ab9a-f8f68935622b 2001:db8:a41:2::/64 |
| fa52b704-7b3c-4c83-8698-244807352711 | internal | 301b3e63-5324-4d62-8e22-ed8dddd50689 10.65.0.0/16        |
|                                      |          | bf94ccb1-c57c-4c9a-a873-c20cbfa4ecaf 2001:db8:a41:3::/64 |
+--------------------------------------+----------+----------------------------------------------------------+
```
{: .no-select-button}

Next, check the details of the `external` network.

```bash
neutron net-show external
```

It should return something like the following.

```
+---------------------------+--------------------------------------+
| Field                     | Value                                |
+---------------------------+--------------------------------------+
| admin_state_up            | True                                 |
| id                        | 8d5dec25-a6aa-4e18-8706-a51637a428c2 |
| name                      | external                             |
| provider:network_type     | local                                |
| provider:physical_network |                                      |
| provider:segmentation_id  |                                      |
| router:external           | True                                 |
| shared                    | True                                 |
| status                    | ACTIVE                               |
| subnets                   | 54db559c-5e1d-4bdc-83b0-c479ef2a0ead |
|                           | cf6ceea0-dde0-4018-ab9a-f8f68935622b |
| tenant_id                 | ed34337f935745bb911eeb741bc4374b     |
+---------------------------+--------------------------------------+
```
{: .no-select-button}

Check the details of the `internal` network.

```bash
neutron net-show internal
```
It should return something like the following.

```
+---------------------------+--------------------------------------+
| Field                     | Value                                |
+---------------------------+--------------------------------------+
| admin_state_up            | True                                 |
| id                        | fa52b704-7b3c-4c83-8698-244807352711 |
| name                      | internal                             |
| provider:network_type     | local                                |
| provider:physical_network |                                      |
| provider:segmentation_id  |                                      |
| router:external           | False                                |
| shared                    | True                                 |
| status                    | ACTIVE                               |
| subnets                   | 301b3e63-5324-4d62-8e22-ed8dddd50689 |
|                           | bf94ccb1-c57c-4c9a-a873-c20cbfa4ecaf |
| tenant_id                 | ed34337f935745bb911eeb741bc4374b     |
+---------------------------+--------------------------------------+
```
{: .no-select-button}

Check the `external4` subnet.

```bash
neutron subnet-show external4
```

It should return something like the following.

```
+------------------+----------------------------------------------------+
| Field            | Value                                              |
+------------------+----------------------------------------------------+
| allocation_pools | {"start": "172.18.208.2", "end": "172.18.208.255"} |
| cidr             | 172.18.208.0/24                                    |
| dns_nameservers  |                                                    |
| enable_dhcp      | True                                               |
| gateway_ip       | 172.18.208.1                                       |
| host_routes      |                                                    |
| id               | 54db559c-5e1d-4bdc-83b0-c479ef2a0ead               |
| ip_version       | 4                                                  |
| name             | external4                                          |
| network_id       | 8d5dec25-a6aa-4e18-8706-a51637a428c2               |
| tenant_id        | ed34337f935745bb911eeb741bc4374b                   |
+------------------+----------------------------------------------------+
```
{: .no-select-button}

Check the `external6` subnet.

```bash
neutron subnet-show external6
```

It should return something like the following.

```
+------------------+-----------------------------------------------------------------------------+
| Field            | Value                                                                       |
+------------------+-----------------------------------------------------------------------------+
| allocation_pools | {"start": "2001:db8:a41:2::2", "end": "2001:db8:a41:2:ffff:ffff:ffff:fffe"} |
| cidr             | 2001:db8:a41:2::/64                                                         |
| dns_nameservers  |                                                                             |
| enable_dhcp      | True                                                                        |
| gateway_ip       | 2001:db8:a41:2::1                                                           |
| host_routes      |                                                                             |
| id               | cf6ceea0-dde0-4018-ab9a-f8f68935622b                                        |
| ip_version       | 6                                                                           |
| name             | external6                                                                   |
| network_id       | 8d5dec25-a6aa-4e18-8706-a51637a428c2                                        |
| tenant_id        | ed34337f935745bb911eeb741bc4374b                                            |
+------------------+-----------------------------------------------------------------------------+
```
{: .no-select-button}

Part 3: Start using your networks
---------------------------------

At this stage, all configuration is done! When you spin up a new VM, you
have to decide if you want it to be contactable from outside the data
center. If you do, give it a network interface on the `external`
network: otherwise, give it one on the `internal` network. Obviously, a
machine that originally wasn't going to be reachable can be made
reachable by plugging a new interface into it on the `external` network.

Right now we don't support address mobility, so an address is tied to a
single port until that port is no longer in use. We plan to address this
in the future.

The next step in configuring your OpenStack deployment is to configure
security. We'll have a document addressing this shortly.
