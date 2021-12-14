## Kernel dependencies

> **Tip**: If you are using one of the recommended distributions, you will already
> satisfy these. 
{: .alert .alert-success}

- `ip_set`
- `ip_tables` (for IPv4)
- `ip6_tables` (for IPv6)
- `ipt_REJECT`
- `ipt_rpfilter`
- `ipt_set`
- `nf_conntrack_netlink` subsystem
- `nf_conntrack_proto_sctp`
- `sctp`
- `xt_addrtype`
- `xt_comment`
- `xt_conntrack`
- `xt_icmp` (for IPv4)
- `xt_icmp6` (for IPv6)
- `xt_ipvs`,`ipt_ipvs`
- `xt_mark`
- `xt_multiport`
- `xt_rpfilter`
- `xt_sctp`
- `xt_set`
- `xt_u32`
- `xt_bpf` (for eBPF)
- `vfio-pci`
- `ipip` (if using {{site.prodname}} networking in IPIP mode)
- `wireguard` (if using WireGuard encryption)
