// Copyright (c) 2019 Tigera, Inc. All rights reserved.

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>
#include <stdint.h>

#include "bpf.h"
#include "bpf_maps.h"

static CALICO_BPF_INLINE int mac_sw_redir(struct xdp_md *xdp) {
    void *data_start = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth_hdr = data_start;

    // Need to check bounds before accessing packet and verifier polices this.
    void *next_header = (void *)(eth_hdr+1);
    if (next_header > data_end) {
        return XDP_DROP;
    }

    if (eth_hdr->h_proto != host_to_be16(ETH_P_IP)) {
        // Allow non-IP through (e.g. ARPs)
        return XDP_PASS;
    }

    // Have an IP packet, extract its header and bounds check.
    struct iphdr *ip_header = next_header;
    if (next_header + sizeof(*ip_header) > data_end) {
        return XDP_DROP;
    }
    int ip_header_len = ip_header->ihl * 4;
    next_header += ip_header_len;
    if (next_header > data_end) {
        return XDP_DROP;
    }

    // Look up the destination.
    struct calico_mac_sw_value *value = bpf_map_lookup_elem(&calico_mac_sw_map, &ip_header->daddr);
    if (!value) {
        return XDP_PASS;
    }

    // Update the MACs.
    __builtin_memcpy(&eth_hdr->h_source, &value->new_src, sizeof(eth_hdr->h_source));
    __builtin_memcpy(&eth_hdr->h_dest, &value->new_dst, sizeof(eth_hdr->h_dest));

//    // Packets exiting a veth tend to have incorrect checksums.  Since XDP doesn't do any hardware offload,
//    // fix up now.
//    if (ip_header->protocol == 6 /* TCP */ && value->flags & 0x1) {
//        struct tcphdr *tcp_header = next_header;
//        next_header = (void *)(tcp_header + 1);
//        if (next_header > data_end) {
//            return XDP_DROP;
//        }
//        tcp_header->check = 0;
//    }

    // Redirect the packet.
    return bpf_redirect_map(&calico_ifaces_map, value->dst_iface, 0);
}


__attribute__((section("mac_sw_redir")))
int xdp_mac_sw_redir(struct xdp_md *xdp) {
    return mac_sw_redir(xdp);
}

__attribute__((section("allow_all")))
int xdp_allow_all(struct xdp_md *xdp)
{
	return XDP_PASS;
}

__attribute__((section("allow_all")))
int xdp_drop_all(struct xdp_md *xdp)
{
	return XDP_DROP;
}
