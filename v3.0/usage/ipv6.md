---
title: IPv6 Support
sitemap: false 
canonical_url: https://docs.projectcalico.org/v3.1/usage/ipv6
---

Calico supports connectivity over IPv6, between compute hosts, and
between compute hosts and their VMs. This means that, subject to
security configuration, a VM can initiate an IPv6 connection to another
VM, or to an IPv6 destination outside the data center; and that a VM can
terminate an IPv6 connection from outside.

## Requirements for containers

Containers have no specific requirements for utilising IPv6
connectivity.


## Implementation details

Following are the key points of how IPv6 connectivity is currently
implemented in Calico.

-   IPv6 forwarding is globally enabled on each compute host.
-   Felix (the Calico agent):
    -   does `ip -6 neigh add lladdr dev`, instead of IPv4 case
        `arp -s`, for each endpoint that is created with an IPv6 address
    -   adds a static route for the endpoint's IPv6 address, via its tap
        or veth device, just as for IPv4.
-   Dnsmasq provides both Router Advertisements and DHCPv6 service
    (neither of which are required for container environments).
    -   Router Advertisements, without SLAAC or on-link flags, cause
        each VM to create a default route to the link-local address of
        the VM's TAP device on the compute host.
    -   DHCPv6 allows VMs to get their orchestrator-allocated
        IPv6 address.
-   For container environments, we don't Dnsmasq:
    -   rather than using Router Advertisements to create the default
        route, we Proxy NDP to ensure that routes to all machines go via
        the compute host.
    -   rather than using DHCPv6 to allocate IPv6 addresses, we allocate
        the IPv6 address directly to the container interface before we
        move it into the container.
-   BIRD6 runs between the compute hosts to distribute routes.

