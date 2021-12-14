.. _implementation-notes:

====================
Implementation notes
====================

The following notes explain, for an audience that is already familiar with
OpenStack and Neutron, some details of how Calico is implemented.

Connectivity between IP addresses in the default address scope
--------------------------------------------------------------

Each compute host uses Linux to route the data to and from its VMs.  For an
endpoint in the default address scope, everything happens in the default
namespace of its compute hosts.  Standard Linux routing routes VM data, with
iptables used to implement the configured security policy.

A VM is 'plugged' with a TAP device on the host that connects to the VM's
network stack.  The host end of the TAP is left unbridged and without any IP
addresses (except for link-local IPv6).  The host is configured to respond to
any ARP or NDP requests, through that TAP, with its own MAC address; hence data
arriving through the TAP is always addressed at L2 to the host, and is passed
to the Linux routing layer.

For each local VM, the host programs a route to that VM's IP address(es)
through the relevant TAP device.  The host also runs a BGP client (BIRD) so as
to export those routes to other compute hosts.  The routing table on a compute
host might therefore look like this:

.. code::

 user@host02:~$ route -n
 Kernel IP routing table
 Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
 0.0.0.0         172.18.203.1    0.0.0.0         UG    0      0        0 eth0
 10.65.0.21      172.18.203.126  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.22      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.23      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.24      0.0.0.0         255.255.255.255 UH    0      0        0 tapa429fb36-04
 172.18.203.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0

This shows one local VM on this host with IP address 10.65.0.24, accessed via a
TAP named tapa429fb36-04; and three VMs, with the .21, .22 and .23 addresses,
on two other hosts (172.18.203.126 and .129), and hence with routes via those
compute host addresses.

DHCP
----

DHCP service is provided by a DHCP agent that runs on each compute host, that
invokes Dnsmasq using its --bridge-interface option.  The effect of this option
is that Dnsmasq treats all the TAP interfaces as aliases of the ns-XXX
interface where Dnsmasq's DHCP 'context' is defined, in the senses that:

- if a DHCP (v4 or v6) or Router Solicit packet is received on one of the TAP
  interfaces, Dnsmasq processes it as though received on the ns-XXX interface,
  and then sends the response on the relevant TAP

- when Dnsmasq would normally send an unsolicited Router Advertisement on the
  ns-XXX interface, it instead sends it on all of the TAP interfaces.

The DHCP agent is run with a Calico-specific interface driver that creates
ns-XXX as a Linux dummy interface, and that uses the subnet gateway IP as
ns-XXX's IP address, instead of allocating a unique IP address from Neutron.

Patches to allow this behavior were merged into Dnsmasq before its 2.73
release, and into Neutron before its Liberty release.
