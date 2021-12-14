## Kernel dependencies

> **Tip**: If you are using one of the recommended distributions, you will already
> satisfy these. 
{: .alert .alert-success}

Due to the large number of distributions and kernel version out there, it's hard to be precise about the names of the particular kernel modules that are required to run {{site.prodname}}.  However, in general, you'll need:

- The `iptables` modules (both the "legacy" and "nft" variants are supported). These are typically broken up into many small modules, one for each type of match criteria and one for each type of action.  {{site.prodname}} requires:

  - The "base" modules (including the IPv6 versions if IPv6 is enabled in your cluster).
  - At least the following match criteria: `set`, `rpfilter`, `addrtype`, `comment`, `conntrack`, `icmp`, `tcp`, `udp`, `ipvs`, `icmpv6` (if IPv6 is enabled in your kernel), `mark`, `multiport`, `rpfilter`, `sctp`, `ipvs` (if using `kube-proxy` in IPVS mode).
  - At least the following actions: `REJECT`, `ACCEPT`, `DROP`, `LOG`.
 
- IP sets support.
- Netfilter Conntrack support compiled in (with SCTP support if using SCTP).
- IPVS support if using `kube-proxy` in IPVS mode.
- IPIP, VXLAN, Wireguard support, if using {{site.prodname}} networking in one of those modes.
- eBPF (including the `tc` hook support) and XDP (if you want to use the eBPF dataplane).
