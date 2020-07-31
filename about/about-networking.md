---
title: About Networking
description: Learn about networking!
---

You can get up and running with Calico by following any of our getting started guides without needing to be a networking expert. Calico hides the complexities for you.  However, if you would like to learn more about networking, so you can better understand what is happening under the covers, this guide provides a short introduction to some of the key fundamental networking for anyone who is not already familiar with them.

In this guide you will learn:
- The terms used to described different layers of the network.
- The anatomy of a network packet.
- How IP addressing and IP routing works.
- What are MTU, NAT, and DNS.


### Network Layers

The process of sending and receiving data over a network is commonly categorized into 7 layers (referred to as the {% include open-new-window.html text='OSI model' url='https://en.wikipedia.org/wiki/OSI_model' %}). They layers are typically abbreviated as L1 - L7. You can think of data as passing through each of these layers in turn as it is sent or received from an application, which each layer being responsible for a particular part of the processing required to send the data over the network.

![OSI network layers diagram]({{site.baseurl}}/images/osi-network-layers.svg)

In a modern enterprise or public cloud network, the layers commonly map as follows:

- L5-7: all the protocols most application developers are familiar with. e.g. HTTP, FTP, SSH, SSL, DNS.
- L4: TCP or UDP, including source and destination ports.
- L3: IP packets and IP routing.
- L2: Ethernet packets and Ethernet switching.

### Anatomy of a network packet





OSI model, L2, L3, Encap (VXLAN, IPIP), CIDRs, Routing, MTU, NAT, DNS




concepts

A deeper look at L2 and L3
Anatomy of a packet

L2 Header
IP Header
TCP/UDP Header
L4+ Headers
Data
L2 Footer

MTU
IP Addressing
IPv4, IPv6, CIDRs
IP Routing
Overlay Networks
Network Address Translation (NAT)
Overview of Domain Name Service (DNS)

