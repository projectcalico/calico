---
title: Configure OpenStack for IPv6 only or dual stack
description: Configure OpenStack for IPv6 only or dual stack. 
canonical_url: '/networking/openstack/floating-ips'
---

### Big picture

Configure {{site.prodname}} IP address allocation to use IPv6 only or dual stack for workload communications.

### Value

Although communication over IPv6 is increasingly desirable as the natural mode for workloads, it is often a requirement to continue support for IPv4. {{site.prodname}} supports **dual stack**, where new pods get IPv6 and IPv4 addresses, and can communicate with each other and the outside world over IPv6, as well as IPv6-only. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPAM**, a {{site.prodname}} CNI plugin configured with `assign_ipv6` and `assign_ipv4` flags

### Before you begin...

**{{site.prodname}} requirements** 

  {{site.prodname}} IPAM.  
  The defaut mode is **IPv4**.

**Kubernetes version requirements**
  - For dual stack (alpha level), 1.16 and 1.17 
  - For one IP stack at a time (IPv6 or IPv4), 1.15 and earlier 

**Kubernetes IPv6 host requirements**
  - An IPv6 address that is reachable from the other hosts
  - The sysctl setting, `net.ipv6.conf.all.forwarding`, is set to `1`.    
    This ensures both Kubernetes service traffic and {{site.prodname}} traffic is forwarded appropriately.
  - A default IPv6 route

### How to

OpenStack (not {{site.prodname}}) controls whether a VM gets IPv4, IPv6, or both addresses. Calico simply honors the addresses that OpenStack specifies. The following extra steps are required for **IPv6-only** and **dual stack** deployments -- so the guest OS can learn its IPv6 address (if assigned by OpenStack).

1. Verify that the guest VM image meets these requirements for IPv6 connectivity.   

    - When booting up, the VM must issue a DHCPv6 request for each of its interfaces, so that it can learn the IPv6 addresses that OpenStack allocates for it. If the VM uses the widely-deployed **DHCP client from ISC**, it must have a fix/workaround for {% include open-new-window.html text='this known issue' url='https://kb.isc.org/article/AA-01141/31/How-to-workaround-IPv6-prefix-length-issues-with-ISC-DHCP-clients.html' %}. 
    - The VM must be configured to accept router advertisements. 

   Although not all common cloud images meet these requirements yet, it is easy to remedy by launching an image, making appropriate changes to its configuration files, taking a snapshot, and then using the snapshot thereafter instead of the original image.

   For example, starting from an **Ubuntu cloud image**, the following changes meet the requirements listed.

   -   In `/etc/network/interfaces.d/eth0.cfg`, add:
   
           iface eth0 inet6 dhcp
                   accept_ra 1
   
   -   In `/sbin/dhclient-script`, add at the start of the script:
   
           new_ip6_prefixlen=128
   
   -   In `/etc/sysctl.d`, create a file named `30-eth0-rs-delay.conf` with
       contents:
   
           net.ipv6.conf.eth0.router_solicitation_delay = 10

   For **CentOS**, these additions to a cloud-init script have been reported to be effective:

     runcmd:
     - sed -i -e '$a'"IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
     - sed -i -e '$a'"DHCPV6C=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
     - sed -i '/PATH/i\new_ip6_prefixlen=128' /sbin/dhclient-script
     - systemctl restart network

1. Configure IPv6 support in {{site.prodname}} by defining an IPv6 subnet in each Neutron network with:

   - The IPv6 address range that you want your VMs to use
   - DHCP enabled
   - From Juno onwards, IPv6 address mode set to DHCPv6 stateful

   We suggest that you initially configure both IPv4 and IPv6 subnets in each network. This allows handling VM images that support only IPv4 alongside those that support both IPv4 and IPv6, and allows a VM to be accessed over IPv4 in case this is needed to troubleshoot any issues with its IPv6 configuration. In principle, though, we are not aware of any problems with configuring and using IPv6-only networks in OpenStack.