IPv6 support
============

**In the currently release of Calico (0.12.1) IPv6 is temporarily
non-functional. We aim to fix this in the next release.**

Calico supports connectivity over IPv6, between compute hosts, and
between compute hosts and their VMs. This means that, subject to
security configuration, a VM can initiate an IPv6 connection to another
VM, or to an IPv6 destination outside the data center; and that a VM can
terminate an IPv6 connection from outside.

Requirements on guest VM images
-------------------------------

IPv6 connectivity requires some things of the guest VM image:

-  When it boots up, the VM should issue a DHCPv6 request for each of
   its interfaces, so that it can learn the IPv6 addresses that
   OpenStack has allocated for it.

-  The VM must be configured to accept Router Advertisements.

-  If it uses the widely deployed DHCP client from ISC, the VM must have
   a fix or workaround for this known issue:
   https://kb.isc.org/article/AA-01141/31/How-to-workaround-IPv6-prefix-length-issues-with-ISC-DHCP-clients.html.

-  When it boots up, the VM should wait a short while (say, 10 seconds)
   before sending a Router Solicit message for each of its interfaces,
   to ensure that the communication path to the Router Advertisement
   daemon is ready. This is a pragmatic workaround for a bug
   (https://github.com/Metaswitch/calico/issues/12) that needs further
   investigation, and should become unnecessary when that bug is
   resolved.

These requirements are not yet all met in common cloud images - but it
is easy to remedy that by launching an image, making appropriate changes
to its configuration files, taking a snapshot, and then using that
snapshot thereafter instead of the original image.

For example, starting from the Ubuntu 14.04 cloud image, the following
changes will suffice to meet the requirements just listed.

-  In /etc/network/interfaces.d/eth0.cfg, add:

   ::

       iface eth0 inet6 dhcp
               accept_ra 1

-  In /sbin/dhclient-script, add at the start of the script:

   ::

       new_ip6_prefixlen=128

-  In /etc/sysctl.d, create a file named 30-eth0-rs-delay.conf with
   contents:

   ::

       net.ipv6.conf.eth0.router_solicitation_delay = 10

Technical details
-----------------

Following are the key points of how IPv6 connectivity is currently
implemented in Calico.

-  IPv6 forwarding is globally enabled on each compute host.

-  Felix (the Calico agent):

   -  does “ip -6 neigh add lladdr dev ”, instead of IPv4 case “arp -s ”,
      for each VM that is created with an IPv6 address

   -  adds a static route for the VM's IPv6 address, via its TAP device,
      similarly as for IPv4.

-  Dnsmasq provides both Router Advertisements and DHCPv6 service.

   -  Router Advertisements, without SLAAC or on-link flags, cause each VM
      to create a default route to the link-local address of the VM's TAP
      device on the compute host.

   -  DHCPv6 allows each VM to get its OpenStack-allocated IPv6 address.

-  BIRD6 runs between the compute hosts, either via a route reflector or
   in a full mesh.

-  A single OpenStack network is configured, with an IPv4 subnet
   (10.65.0/24) and an IPv6 subnet (2001:db8:a41:2::/64), with both
   subnets DHCP-enabled.


