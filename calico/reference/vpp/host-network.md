---
title: Host network configuration
description: Description of the host network configuration performed by VPP.
canonical_url: '/reference/vpp/host-network'
---

### Big picture

The VPP-Host connection is a bit particular in the sense that the address of the primary interface is shared by both VPP and Linux.
Let's say the primary interface (uplink interface on the diagram below) is called `enp216s0f1` and configured with an `192.168.0.1/24` address.

This address must also be the one the api-server will be listening on, as the first address of the uplink (a.k.a main interface for the host).

![Network architecture]({{ site.baseurl }}/images/vpp-host-net.svg)

### When VPP starts
* It grabs the primary interface with the chosen driver, either placing it in a dedicated network namespace, or removing it entirely as a Linux netdev depending on the driver. In any case, the interface disappears from the host's root network namespace
* It configures it in VPP with the same configuration (addresses, routes) it had in Linux

So issuing `show int addr` in VPP will give something like
````
vpp# sh int addr
avf-0/d8/a/0 (up):
  L3 192.168.0.1/24
````
* It creates a `tap` interface between VPP and the host
* This tap interface is given the same name and MAC address as the original interface in the host's root network namespace
* This interface is also reconfigured with all the addresses and routes that the host had configured on the original interface

````bash
ip addr show enp216s0f1
3: enp216s0f1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 52:54:00:40:46:8e brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.1/24 brd 192.168.0.255 scope global eth1
       valid_lft forever preferred_lft forever

ip route
default via 192.168.0.254 dev enp216s0f1 proto dhcp src 192.168.0.1 metric 100
${SERVICE_CIDR} via 192.168.0.254 dev enp216s0f1 proto static mtu 1440
${POD_CIDR} via 192.168.0.254 dev enp216s0f1 proto static mtu 1440
192.168.0.0/24 dev enp216s0f1 proto kernel scope link src 192.168.0.254
````
The new `tap` interface (named `enp216s0f1` in this example) is also configured with routes towards the Kubernetes service CIDR and the pod CIDR, so that the Linux host can reach the workloads through VPP. These routes use a reduced MTU to accommodate for encapsulations.

* In VPP you will find it with the name `tap0`
  * It is configured unnumbered, as a child of the primary interface `avf-0/d8/a/0`
````
vpp# sh int addr
tun0 (up):
  unnumbered, use avf-0/d8/a/0
  L3 192.168.0.1/24
````
* It is also registered as the default punt path
  * This means that all the traffic that would be dropped by VPP (which includes the traffic to the VPP address that is not handled by VPP itself, but not the tunnel traffic which is decapsulated / decrypted by VPP) will be passed to this interface, so the Linux host will receive and process it
````
vpp# sh ip punt redirect
 rx local0 via:
   path-list:[31] locks:1 flags:no-uRPF, uPRF-list:24 len:1 itfs:[2, ]
    path:[41] pl-index:31 ip4 weight=1 pref=0 attached-nexthop:  oper-flags:resolved,
      169.254.0.1 tap0
    [@0]: ipv4 via 169.254.0.1 tap0: mtu:1500 next:6 flags:[features ] 52540040468e02ca11c0fd100800
 forwarding
  [@1]: ipv4 via 169.254.0.1 tap0: mtu:1500 next:6 flags:[features ] 52540040468e02ca11c0fd100800
# For the v6 configuration, use
vpp# sh ip6 punt redirect
````

### Packet flow - incoming packet on the uplink

A packet destined to the host arrives on the uplink, let's say it has `src=192.168.0.2,dst=192.168.0.1`
* VPP receives it, sees that the destination address is the one configured on its interface
* As it doesn't have specific handling configured for this packet, it looks up the punt path, and sends it into `tap0`
* Linux receives it on the tap interface which is configured with `192.168.0.1/32` and so processes it normally

The reply is now emitted by the host with `src=192.168.0.1,dst=192.168.0.2`
* Linux looks up the route for `192.168.0.0/24`, forwards it into the tap interface
* VPP receives it on the interface `tap0`
* It looks up `192.168.0.2` in the fib, finds a route on the uplink interface (configured with `192.168.0.1/24`)
* The packet is sent on the uplink

### Packet flow - pod talking to the api-server

Let's say the api server lives on `Node A`.

If a pod on `Node B` wants to talk to the api-server on `Node A`, the packet flow will be the same as described above.
* In `Node B`, standard routing happens (`sh ip fib <someip>` will give details on this node)
* When reaching `Node A`, we're in the same situation as previously

If a pod on `Node A` wants to talk to the api-server on `Node A`, let's say the packet is `src=10.0.0.1,dst=192.168.0.1` with `10.0.0.1` being the pod address, then:
* Things happen exactly the same way as if the packet was coming from the uplink
* This time packets come into vpp through `tunN` corresponding to the pod interface, and is then punted to `tap0` towards the host
* The return traffic from the host is received by VPP on `tap0`, and is routed directly to the pod on `tunN`

