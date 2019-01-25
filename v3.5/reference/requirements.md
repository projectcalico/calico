---
title: Calico System Requirements
redirect_from: latest/reference/requirements
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/requirements'
---

Depending on the {{site.prodname}} functionality you are using, there are some requirements your system needs to meet in order for {{site.prodname}} to work properly.
`{{site.nodecontainer}}` container image ships with the following `ip6tables`, `ipset`, `iputils`, `iproute2`, `conntrack-tools`.

## Minumum Linux kernel versions

IPv4 only: `2.6.32`

IPv6: `3.10`

## Requirements for {{site.prodname}} Policy:

### iproute2
 
 iproute2 is a collection of utilities for controlling TCP/IP networking and traffic control in Linux.
 
 **Shared libraries dependencies**:
  - `glibc`
  - `libelf`
 
### iputils 

The iputils package is set of small useful utilities for Linux networking.
 
 **Shared libraries dependencies**:
  - `libcap`
  - `libidn`
  - `openssl`
  - `sysfsutils`
 
### conntrack 

The [conntrack-tools](http://www.netfilter.org/projects/conntrack-tools/index.html) are a set of tools to manage the in-kernel connection tracking state table from userspace.
 
 **Minimum required version**: `1.4.1` 
 
 **Kernel dependencies**: 
 - `nf_conntrack_netlink` subsystem
    - `nf_conntrack`
    - `nfnetlink`
 
 **Shared libraries dependencies**:
  - `libnetfilter_conntrack` 
  - `libnfnetlink` 
  - `libmnl`
  - `libnetfilter_cttimeout`
 
This is included in kernel version `2.6.18` and above.
 
### iptables / ip6tables

[iptables](http://www.netfilter.org/projects/iptables/index.html) is a command line utility for configuring Linux kernel firewall implemented within the [Netfilter](http://www.netfilter.org) project.
 
 **Minimum required version**: `1.4.7` 
 
 **Kernel dependencies**: 
 - `ip_tables` (for IPv4)
    - `x_tables`
 - `ip6_tables` (for IPv6)
    - `x_tables`
 
 **Shared libraries dependencies**:
  - `glibc`
  - `libnftnl`
  - `libpcap`
 
`x_tables` has the shared code used by `iptables` modules.
 This is included in kernel version `2.4` and above.
 
### ipset 

[ipset](http://ipset.netfilter.org/) is used to set up, maintain and inspect so called IP sets in the Linux kernel.
 
 **Minimum required version**: `6.11`
 
 **Kernel modules dependencies**: 
 - `ip_set`
    - `nfnetlink`
 
### iptables match features

`xt_mark`
   - `x_tables`
    
`xt_addrtype` (`ipt_addrtype`, `ip6t_addrtype`) 
   - `x_tables`

`xt_multiport`
   - `x_tables`
 
### Other required kernel features

`xt_set`: Kernel module which implements the set match and SET target for netfilter/iptables.
 - `ip_set`
 - `x_tables`
 
`ipt_set`: Kernel module to match an IP set.
 - `x_tables`
 - `ip_set`
 
`ipt_rpfilter`: Kernel module to match RPF.

`ipt_REJECT`: Kernel module to reject packets.

## Requirements for {{site.prodname}} Networking:
 
### IP-in-IP Tunneling

IP tunnel driver to provide an IP tunnel through which you can tunnel network traffic transparently across subnets.

 - `ipip`
    - `ip_tunnel`
    - `tunnel4`
