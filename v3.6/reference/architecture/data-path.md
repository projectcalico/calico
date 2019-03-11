---
title: 'The Calico data path: IP routing and iptables'
redirect_from: latest/reference/architecture/data-path
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/architecture/data-path'
---


One of Calico’s key features is how packets flow between workloads in a
data center, or between a workload and the Internet, without additional
encapsulation.

In the Calico approach, IP packets to or from a workload are routed and
firewalled by the Linux routing table and iptables infrastructure on the
workload’s host. For a workload that is sending packets, Calico ensures
that the host is always returned as the next hop MAC address regardless
of whatever routing the workload itself might configure. For packets
addressed to a workload, the last IP hop is that from the destination
workload’s host to the workload itself.

![Calico datapath]({{site.baseurl}}/images/calico-datapath.png)

Suppose that IPv4 addresses for the workloads are allocated from a
datacenter-private subnet of 10.65/16, and that the hosts have IP
addresses from 172.18.203/24. If you look at the routing table on a host:

```bash
route -n
```

You will see something like this:

```bash
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.18.203.1    0.0.0.0         UG    0      0        0 eth0
10.65.0.0       0.0.0.0         255.255.0.0     U     0      0        0 ns-db03ab89-b4
10.65.0.21      172.18.203.126  255.255.255.255 UGH   0      0        0 eth0
10.65.0.22      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
10.65.0.23      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
10.65.0.24      0.0.0.0         255.255.255.255 UH    0      0        0 tapa429fb36-04
172.18.203.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0
```
{: .no-select-button}

There is one workload on this host with IP address 10.65.0.24, and
accessible from the host via a TAP (or veth, etc.) interface named
tapa429fb36-04. Hence there is a direct route for 10.65.0.24, through
tapa429fb36-04. Other workloads, with the .21, .22 and .23 addresses,
are hosted on two other hosts (172.18.203.126 and .129), so the routes
for those workload addresses are via those hosts.

The direct routes are set up by a Calico agent named Felix when it is
asked to provision connectivity for a particular workload. A BGP client
(such as BIRD) then notices those and distributes them – perhaps via a
route reflector – to BGP clients running on other hosts, and hence the
indirect routes appear also.

## Bookended security

The routing above in principle allows any workload in a data center to
communicate with any other – but in general, an operator will want to
restrict that; for example, so as to isolate customer A’s workloads from
those of customer B. Therefore Calico also programs iptables on each
host, to specify the IP addresses (and optionally ports etc.) that each
workload is allowed to send to or receive from. This programming is
‘bookended’ in that the traffic between workloads X and Y will be
firewalled by both X’s host and Y’s host – this helps to keep unwanted
traffic off the data center’s core network, and as a secondary defense
in case it is possible for a rogue workload to compromise its local
host.

## Is that all?

As far as the static data path is concerned, yes. It’s just a
combination of responding to workload ARP requests with the host MAC, IP
routing and iptables. There’s a great deal more to Calico in terms of
how the required routing and security information is managed, and for
handling dynamic things such as workload migration – but the basic data
path really is that simple.
