IPv6 Support
============

Calico supports connectivity over IPv6, between compute hosts, and
between compute hosts and their VMs. This means that, subject to
security configuration, a VM can initiate an IPv6 connection to another
VM, or to an IPv6 destination outside the data center; and that a VM can
terminate an IPv6 connection from outside.

Requirements for containers
---------------------------

Containers have no specific requirements for utilising IPv6 connectivity.

Requirements for guest VM images
--------------------------------

When using Calico with a VM platform (e.g. OpenStack), obtaining IPv6
connectivity requires certain configuration in the guest VM image:

-  When it boots up, the VM should issue a DHCPv6 request for each of
   its interfaces, so that it can learn the IPv6 addresses that
   OpenStack has allocated for it.

-  The VM must be configured to accept Router Advertisements.

-  If it uses the widely deployed DHCP client from ISC, the VM must have
   a fix or workaround for `this known issue`_.

-  When it boots up, the VM should wait a short while (say, 10 seconds)
   before sending a Router Solicit message for each of its interfaces,
   to ensure that the communication path to the Router Advertisement
   daemon is ready. This is a pragmatic workaround for `a bug`_ that needs
   further investigation, and should become unnecessary when that bug is
   resolved.

These requirements are not yet all met in common cloud images - but it
is easy to remedy that by launching an image, making appropriate changes
to its configuration files, taking a snapshot, and then using that
snapshot thereafter instead of the original image.

For example, starting from the Ubuntu 14.04 cloud image, the following
changes will suffice to meet the requirements just listed.

-  In ``/etc/network/interfaces.d/eth0.cfg``, add:

   ::

       iface eth0 inet6 dhcp
               accept_ra 1

-  In ``/sbin/dhclient-script``, add at the start of the script:

   ::

       new_ip6_prefixlen=128

-  In ``/etc/sysctl.d``, create a file named ``30-eth0-rs-delay.conf`` with
   contents:

   ::

       net.ipv6.conf.eth0.router_solicitation_delay = 10

.. _this known issue: https://kb.isc.org/article/AA-01141/31/How-to-workaround-IPv6-prefix-length-issues-with-ISC-DHCP-clients.html
.. _a bug: https://github.com/Metaswitch/calico/issues/12

Implementation details
----------------------

Following are the key points of how IPv6 connectivity is currently
implemented in Calico.

-  IPv6 forwarding is globally enabled on each compute host.

-  Felix (the Calico agent):

   -  does ``ip -6 neigh add lladdr dev``, instead of IPv4 case ``arp -s``,
      for each endpoint that is created with an IPv6 address

   -  adds a static route for the endpoint's IPv6 address, via its tap or veth
      device, just as for IPv4.

-  Dnsmasq provides both Router Advertisements and DHCPv6 service (neither of
   which are required for container environments).

   -  Router Advertisements, without SLAAC or on-link flags, cause each VM
      to create a default route to the link-local address of the VM's TAP
      device on the compute host.

   -  DHCPv6 allows VMs to get their orchestrator-allocated IPv6 address.

-  For container environments, we don't Dnsmasq:

   - rather than using Router Advertisements to create the default route, we
     Proxy NDP to ensure that routes to all machines go via the compute host.

   - rather than using DHCPv6 to allocate IPv6 addresses, we allocate the IPv6
     address directly to the container interface betfore we move it into the
     container.

-  BIRD6 runs between the compute hosts to distribute routes.

OpenStack Specific Details
~~~~~~~~~~~~~~~~~~~~~~~~~~

For OpenStack, IPv6 works best when each OpenStack network is configured with
both an IPv4 and IPv6 subnet with DHCP enabled, at least initially. This makes
it possible to seamlessly handle VM images that support only IPv4 alongside
those that support both, and guarantees it will be possible to access
misconfigured VM images over IPv4.

However, we do not believe there are any problems with providing an
IPv6-only network in OpenStack.
