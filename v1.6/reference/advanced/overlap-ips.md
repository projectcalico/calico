---
title: Overlapping IPv4 address ranges
sitemap: false 
---
This document describes how we can use 464XLAT to allow multiple tenants within the same data center to use the same IPv4 address ranges (including actually using the same IPv4 addresses). This is known as “overlapping” IPv4 addresses, and also as “address space isolation”, because it means that an IP address such as 10.10.0.2 (for example) for one tenant has nothing to do with the same IP address being used by a different tenant.

## RFC 6877
464XLAT is specified by [RFC 6877](https://tools.ietf.org/html/rfc6877) and describes how an IPv4-based application on a client device can access IPv4-based services somewhere in the Internet, via an IPv6 network.

- An IPv4 packet sent from the client’s application is translated (statelessly, per [RFC 6145](https://tools.ietf.org/html/rfc6145) into an IPv6 packet.
```
IPv4 packet           IPv6 packet
SRC 192.168.0.2 ----> SRC 2001:db8:a41:23::192.168.0.2
DST 72.51.34.34       DST 2001:db8:a41:23::72.51.34.34
```
- The IPv6 packet is routed over the IPv6 network to the relevant server.
- The IPv6 packet is translated back into an IPv4 packet. This step needs to be stateful (per [RFC 6146](https://tools.ietf.org/html/rfc6146)) because an arbitrary number of clients can connect to the server, and it isn’t possible to map all their possible IPv6 addresses onto a range of IPv4 addresses in any way that’s reversible without state.
```
IPv6 packet                            IPv4 packet
SRC 2001:db8:a41:23::192.168.0.2 ----> SRC 192.168.11.5
DST 2001:db8:a41:23::72.51.34.34       DST 72.51.34.34
```
- The IPv4 packet is delivered to the server application, and the server application responds.
- The response IPv4 packet is translated into an IPv6 packet. This uses the state established by the incoming packet, in particular to translate the response packet’s destination IPv4 address to an IPv6 address.
```
IPv4 packet            IPv6 packet
SRC 72.51.34.34  ----> SRC 2001:db8:a41:23::72.51.34.34
DST 192.168.11.5       DST 2001:db8:a41:23::192.168.0.2
```
- The response IPv6 packet is routed over the IPv6 network back to the client.
- The response IPv6 packet is translated back into an IPv4 packet.
```
IPv6 packet                            IPv4 packet
SRC 2001:db8:a41:23::72.51.34.34 ----> SRC 72.51.34.34
DST 2001:db8:a41:23::192.168.0.2       DST 192.168.0.2
```
- The response IPv4 packet is delivered to the client application.

## Data center usage
The use of 464XLAT for overlapping IPv4 addresses in a data center is largely similar. In particular:

- An IPv4 packet coming from an instance is translated to IPv6 by the compute host.
- The core transport of the data center, i.e. the L3 network connecting the compute hosts to each other, is IPv6 only.
- An IPv6 packet that arrives on a compute host, and that is destined for an instance on that compute host, is translated back to an IPv4 packet and then routed to the relevant instance.
Allowing multiple tenants to use the same IPv4 address ranges is achieved by including a number in the IPv6 translation that represents the tenant - or more generally, that represents the address space. So, an IPv4 address W.X.Y.Z, in address space `<ID>`, would be mapped to the IPv6 address:

```
<prefix>:<ID>::W.X.Y.Z
```

The address space needs to be associated, on each compute host, with the TAP interfaces of all VM ports whose IPv4 addresses are to be considered as belonging to that address space. Then, when an IPv4 packet is received by the compute host on one of those TAP interfaces, it can be translated to an IPv6 packet whose addresses contain the correct `<ID>`.

There are many possible mappings between tenants and address spaces.

Complete tenant isolation corresponds to an address space that is only allowed to be used by that tenant.
The current non-isolated Calico model corresponds to an address space that is shared across all tenants.
Between these extremes, it is also possible for an address space to be shared by a specific group of tenants.
Also note that a given tenant may use multiple address spaces – for example, one that is private to itself, and one that is shared.

Compute host processing
How might this look in detail, on a given compute host?

TAYGA (http://www.litech.org/tayga/) is an open source daemon that translates between IPv4 and IPv6. It presents itself as a network device, to which packets wanting translation should be routed. A packet received from a VM will pass through Linux routing and iptables processing twice: once as an IPv4 packet, which routing should direct into the TAYGA device; and then again as an IPv6 packet, which routing should forward to the IPv6 next hop.

Routing namespaces may be needed, as the compute host may have VMs using the same IPv4 addresses in different address spaces; for example two packets, both addressed to 10.10.0.2 but from different VMs, might need to be translated using different address space IDs. Possibly this might be achievable by some marking scheme instead of by using namespaces - TBD.

To route translated packets across the network between compute hosts, BGP must distribute IPv6-translated addresses for instances, instead of the original IPv4 addresses.

So the picture for processing a packet from a VM looks like this:

```
                   +---------------------+
                   | Compute Host        |
                   |                     |
+----+   TAP i/f   |  +---------------+  |
| VM |-------------|--| IPv4 routing  |  |
+----+ IPv4 packet |  |  and iptables |  |
                   |  +---------------+  |
                   |          |          |
                   |  +---------------+  |
                   |  | TAYGA device  |  |
                   |  | xlate to IPv6 |  |
                   |  +---------------+  |
                   |          |          |
                   |  +---------------+  |
                   |  | IPv6 routing  |  |
                   |  | and ip6tables |--|--- IPv6 next hop
                   |  +---------------+  |
                   |                     |
                   +---------------------+
```

For a packet received on a compute host, the first step is to decide whether the packet’s destination IPv6 address maps to one of that compute host’s VMs, and if so directing it into the TAYGA device for translation. This can be done with routing table entries like those that Calico programs today, but with IPv6 addresses and pointing to TAYGA instead of down TAP interfaces.

After translation back to IPv4, the traditional Calico routing rules will route down the correct TAP interface. Except that we have the namespace problem again: if there are two local VMs with the same address, which of them should get the packet?

## Further study and questions
Further work will be needed on (at least) the following points.

Pin down the use of namespaces and/or an alternative marking scheme, on the compute host. If multiple namespaces are used, does this require a separate TAYGA device in each namespace?

One key difference between the RFC 6877 client-server scenario and the data center scenario is that in the data center case we expect that the IPv6->IPv4 translation can be stateless. Broadly, because all of the possible IPv4 source addresses can be represented as themselves on the destination compute host. Need to further pin down and describe precisely whether and why this is true.

How does IPv4<->6 translation interact with external access? Or, how does a VM with an overlapped IPv4 address communicate with an IPv4-based server outside the data center? I think that answering this depends on first pinning down our more general external access story.