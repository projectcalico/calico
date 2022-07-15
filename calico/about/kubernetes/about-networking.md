---
title: About Networking
description: Learn about networking!
---

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, not specific to {{site.prodname}}.
{: .alert .alert-info}

You can get up and running with Calico by following any of the {{site.prodname}} [install
guides]({{site.baseurl}}/getting-started/) without needing to be a networking expert. Calico hides the complexities for
you.  However, if you would like to learn more about networking so you can better understand what is happening under the
covers, this guide provides a short introduction to some of the key fundamental networking concepts for anyone who is
not already familiar with them.

In this guide you will learn:
- The terms used to described different layers of the network.
- The anatomy of a network packet.
- What MTU is and why it makes a difference.
- How IP addressing, subnets, and IP routing works.
- What an overlay network is.
- What DNS and NAT are.

### Network layers

The process of sending and receiving data over a network is commonly categorized into 7 layers (referred to as the {%
include open-new-window.html text='OSI model' url='https://en.wikipedia.org/wiki/OSI_model' %}). The layers are
typically abbreviated as L1 - L7. You can think of data as passing through each of these layers in turn as it is sent or
received from an application, with each layer being responsible for a particular part of the processing required to
send or receive the data over the network.

![OSI network layers diagram]({{site.baseurl}}/images/osi-network-layers.svg)

In a modern enterprise or public cloud network, the layers commonly map as follows:

- L5-7: all the protocols most application developers are familiar with. e.g. HTTP, FTP, SSH, SSL, DNS.
- L4: TCP or UDP, including source and destination ports.
- L3: IP packets and IP routing.
- L2: Ethernet packets and Ethernet switching.

### Anatomy of a network packet

When sending data over the network, each layer in the network stack adds its own header containing the control/metadata
the layer needs in order to process the packet as it traverses the network, passing the resulting packet on to the next
layer of the stack. In this way the complete packet is produced, which includes all the control/metadata required by
every layer of the stack, without any layer understanding the data or needing to process the control/metadata of
adjacent network layers. 

![Anatomy of a network packet]({{site.baseurl}}/images/anatomy-of-a-packet.svg)

### IP addressing, subnets and IP routing

The L3 network layer introduces IP addresses and typically marks the boundary between the part of networking that
application developers care about, and the part of networking that network engineers care about. In particular
application developers typically regard IP addresses as the source and destination of the network traffic, but have much
less of a need to understand L3 routing or anything lower in the network stack, which is more the domain of network
engineers.

There are two variants of IP addresses: IPv4 and IPv6.

- IPv4 addresses are 32 bits long and the most commonly used. They are typically represented as 4 bytes in decimal (each
  0-255) separated by dots. e.g. `192.168.27.64`. There are several ranges of IP addresses that are reserved as
  "private", that can only be used within local private networks, are not routable across the internet. These can be
  reused by enterprises as often as they want to. In contrast "public" IP addresses are globally unique across the whole
  of the internet. As the number of network devices and networks connected to the internet has grown, public IPv4
  addresses are now in short supply.
- IPv6 addresses are 128 bits long and designed to overcome the shortage of IPv4 address space. They are typically
  represented by 8 groups of 4 digit hexadecimal numbers. e.g. `1203:8fe0:fe80:b897:8990:8a7c:99bf:323d`. Due to the 128
  bit length, there's no shortage of IPv6 addresses. However, many enterprises have been slow to adopt IPv6, so for now
  at least, IPv4 remains the default for many enterprise and data center networks.

Groups of IP addresses are typically represented using  {% include open-new-window.html text='CIDR notation'
url='https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing' %} that consists of an IP address and number of
significant bits on the IP address separated by a `/`. For example, `192.168.27.0/24` represents the group of 256 IP
addresses from `192.168.27.0` to `192.168.27.255`.

A group of IP addresses within a single L2 network is referred to as a subnet. Within a subnet, packets can be sent
between any pair of devices as a single network hop, based solely on the L2 header (and footer).

To send packets beyond a single subnet requires L3 routing, with each L3 network device (router) being responsible for
making decisions on the path to send the packet based on L3 routing rules. Each network device acting as a router has
routes that determine where a packet for a particular CIDR should be sent next. So for example, in a Linux system, a
route of `10.48.0.128/26 via 10.0.0.12 dev eth0` indicates that packets with destination IP address in `10.48.0.128/26`
should be routed to a next network hop of `10.0.0.12` over the `eth0` interface.

Routes can be configured statically by an administrator, or programmed dynamically using routing protocols. When using
routing protocols each network device typically needs to be configured to tell it which other network devices it should
be exchanging routes with. The routing protocol then handles programming the right routes across the whole of the
network as devices are added or removed, or network links come in or out of service.

One common routing protocol used in large enterprise and data center networks is {% include open-new-window.html
text='BGP' url='https://en.wikipedia.org/wiki/Border_Gateway_Protocol' %}. BGP is one of the main protocols that powers
the internet, so scales incredibly well, and is very widely supported by modern routers.

### Overlay networks

An overlay network allows network devices to communicate across an underlying network (referred to as the underlay)
without the underlay network having any knowledge of the devices connected to the overlay network. From the point of
view of the devices connected to the overlay network, it looks just like a normal network. There are many different
kinds of overlay networks that use different protocols to make this happen, but in general they share the same common
characteristic of taking a network packet, referred to as the inner packet, and encapsulating it inside an outer network
packet. In this way the underlay sees the outer packets without needing to understand how to handle the inner packets.

How the overlay knows where to send packets varies by overlay type and the protocols they use. Similarly exactly how the
packet is wrapped varies between different overlay types.  In the case of VXLAN for example, the inner packet is wrapped
and sent as UDP in the outer packet.

![Anatomy of an overlay network packet]({{site.baseurl}}/images/anatomy-of-an-overlay-packet.svg)

Overlay networks have the advantage of having minimal dependencies on the underlying network infrastructure, but have
the downsides of:
- having a small performance impact compared to non-overlay networking, which you might want to avoid if running
  network intensive workloads
- workloads on the overlay are not easily addressable from the rest of the network. so NAT gateways or load balancers
  are required to bridge between the overlay and the underlay network for any ingress to, or egress from, the overlay.

{{site.prodname}} networking options are exceptionally flexible, so in general you can choose whether you prefer 
{{site.prodname}} to provide an overlay network, or non-overlay network. You can read more about this in the {{site.prodname}} 
[determine best networking option]({{site.baseurl}}/networking/determine-best-networking) guide.

### DNS

While the underlying network packet flow across the network is determined using IP addresses, users and applications
typically want to use well known names to identify network destinations that remain consistent over time, even if the
underlying IP addresses change. For example, to map `google.com` to `216.58.210.46`. This translation from name to IP
address is handled by {% include open-new-window.html text='DNS' url='https://en.wikipedia.org/wiki/Domain_Name_System'
%}. DNS runs on top of the base networking described so far. Each device connected to a network is typically configured
with the IP addresses of one or more DNS servers. When an application wants to connect to a domain name, a DNS message is
sent to the DNS server, which then responds with information about which IP address(es) the domain name maps to. The
application can then initiate its connection to the chosen IP address.

### NAT

Network Address Translation ({% include open-new-window.html text='NAT'
url='https://en.wikipedia.org/wiki/Network_address_translation' %}) is the process of mapping an IP address in a packet
to a different IP address as the packet passes through the device performing the NAT. Depending on the use case, NAT can
apply to the source or destination IP address, or to both addresses.  

One common use case for NAT is to allow devices with private IP address to talk to devices with public IP address across
the internet. For example, if a device with a private IP address attempts to connect to a public IP address, then the
router at the border of the private network will typically use SNAT (Source Network Address Translation) to map the
private source IP address of the packet to the router's own public IP address before forwarding it on to the internet.
The router then maps response packets coming in the opposite direction back to the original private IP address, so
packets flow end-to-end in both directions, with neither source or destination being aware the mapping is happening. The
same technique is commonly used to allow devices connected to an overlay network to connect with devices outside of the
overlay network.

Another common use case for NAT is load balancing. In this case the load balancer performs DNAT (Destination Network
Address Translation) to change the destination IP address of the incoming connection to the IP address of the chosen
device it is load balancing to. The load balancer then reverses this NAT on response packets so neither source or
destination device is aware the mapping is happening.

### MTU

The Maximum Transmission Unit ({% include open-new-window.html text='MTU'
url='https://en.wikipedia.org/wiki/Maximum_transmission_unit' %}) of a network link is the maximum size of packet that
can be sent across that network link. It is common for all links in a network to be configured with the same MTU to
reduce the need to fragment packets as they traverse the network, which can significantly lower the performance of the
network. In addition, TCP tries to learn path MTUs, and adjust packet sizes for each network path based on the smallest
MTU of any of the links in the network path. When an application tries to send more data than can fit in a single
packet, TCP will fragment the data into multiple TCP segments, so the MTU is not exceeded. 

Most networks have links with an MTU of 1,500 bytes, but some networks support MTUs of 9,000 bytes. In a Linux system,
larger MTU sizes can result in lower CPU being used by the Linux networking stack when sending large amounts of data,
because it has to process fewer packets for the same amount of data. Depending on the network interface hardware being
used, some of this overhead may be offloaded to the network interface hardware, so the impact of small vs large MTU
sizes varies from device to device.

