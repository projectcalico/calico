// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// Utility functions.

static __always_inline void *xdp_data(const struct xdp_md *xdp)
{
	return (void *)(unsigned long)xdp->data;
}

static __always_inline void *xdp_data_end(const struct xdp_md *xdp)
{
	return (void *)(unsigned long)xdp->data_end;
}

static __always_inline bool xdp_no_room(const void *needed, const void *limit)
{
	return needed > limit;
}

static __always_inline
uint16_t get_dest_port_ipv4_tcp(struct xdp_md *ctx, uint64_t nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct tcphdr *tcph;
	uint16_t dport;

	if (iph + 1 > data_end) {
		return 0;
	}
	if (!(iph->protocol == IPPROTO_TCP)) {
		return 0;
	}

	tcph = (void *)(iph + 1);
	if (tcph + 1 > data_end) {
		return 0;
	}

	dport = bpf_ntohs(tcph->dest);
	return dport;
}

static __always_inline
uint16_t get_src_port_ipv4_tcp(struct xdp_md *ctx, uint64_t nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct tcphdr *tcph;
	uint16_t sport;

	if (iph + 1 > data_end) {
		return 0;
	}
	if (!(iph->protocol == IPPROTO_TCP)) {
		return 0;
	}

	tcph = (void *)(iph + 1);
	if (tcph + 1 > data_end) {
		return 0;
	}

	sport = bpf_ntohs(tcph->source);
	return sport;
}

static __always_inline
uint16_t get_dest_port_ipv4_udp(struct xdp_md *ctx, uint64_t nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct udphdr *udph;
	uint16_t dport;

	if (iph + 1 > data_end) {
		return 0;
	}
	if (!(iph->protocol == IPPROTO_UDP)) {
		return 0;
	}

	udph = (void *)(iph + 1);
	if (udph + 1 > data_end) {
		return 0;
	}

	dport = bpf_ntohs(udph->dest);
	return dport;
}

static __always_inline
uint16_t get_src_port_ipv4_udp(struct xdp_md *ctx, uint64_t nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct udphdr *udph;
	uint16_t sport;

	if (iph + 1 > data_end) {
		return 0;
	}
	if (!(iph->protocol == IPPROTO_UDP)) {
		return 0;
	}

	udph = (void *)(iph + 1);
	if (udph + 1 > data_end) {
		return 0;
	}

	sport = bpf_ntohs(udph->source);
	return sport;
}

static __always_inline int veth_main(struct xdp_md *xdp)
{
    // Get L2 protocol and check that it's IP or ARP.
    void *data_end = xdp_data_end(xdp);
    void *data = xdp_data(xdp);
    struct ethhdr *eth = data;
    uint16_t eth_proto;

    printk("Entering veth_main\n");

    if (xdp_no_room(eth + 1, data_end)) {
        printk("Packet too small for ethernet header. Drop.\n");
        return XDP_DROP;
    }

    eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_ARP) {
        // FIXME: allow all ARP for now.
        printk("ARP packet.  Pass.\n");
        return XDP_PASS;
    }
    if (eth_proto != ETH_P_IP) {
        // FIXME: Only IPv4 allowed through for now.
        printk("Not an IPv4 packet (proto %x). Drop.\n", (unsigned int)eth_proto);
        return XDP_DROP;
    }

    // TODO drop fragments

    // Load L3/4 proto/source/dest/ports/etc from packet and see if we have a conntrack entry.
    struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
    uint16_t dest_port, src_port;

    if (xdp_no_room(ipv4_hdr + 1, data_end)) {
        printk("Packet too small for IPv4 header. Drop.\n");
        return XDP_DROP;
    }

    switch (ipv4_hdr->protocol) {
        case IPPROTO_TCP:
            dest_port = get_dest_port_ipv4_tcp(xdp, sizeof(struct ethhdr));
            src_port = get_src_port_ipv4_tcp(xdp, sizeof(struct ethhdr));
            printk("Loaded TCP port %u.\n", (unsigned int)dest_port);
            break;
        case IPPROTO_UDP:
            dest_port = get_dest_port_ipv4_udp(xdp, sizeof(struct ethhdr));
            src_port = get_src_port_ipv4_udp(xdp, sizeof(struct ethhdr));
            printk("Loaded UDP port %u.\n", (unsigned int)dest_port);
            break;
        case IPPROTO_ICMP:
            dest_port = 0;
            src_port = 0;
            break;
        // TODO SCTP
        // TODO ICMP
        default:
            printk("Not a TCP/UDP packet. Drop.\n");
            return XDP_DROP;
    }

    // Do conntrack lookup.
    struct calico_ct_key ct_key;
    __builtin_memcpy(&ct_key.src_addr, &ipv4_hdr->saddr, 4);
    __builtin_memcpy(&ct_key.dst_addr, &ipv4_hdr->daddr, 4);
    ct_key.src_port = src_port;
    ct_key.dst_port = dest_port;
    ct_key.protocol = ipv4_hdr->protocol;

    struct calico_ct_value *ct_value;
    ct_value = map_lookup_elem(&calico_nat_map_v4, &ct_key);
    bool allowed_by_conntrack = false;

    // TODO Drop unexpected TCP packets?  TCP windowing?

    if (ct_value) {
        // Got a conntrack hit, figure out what type.
        switch (ct_value->ct_type) {
        case CALI_CT_TYPE_ALLOW:
            printk("Got conntrack hit: ALLOW.\n");
            allowed_by_conntrack = true;
            break;
        case CALI_CT_TYPE_NAT:
            printk("Got conntrack hit: NAT.\n");
            allowed_by_conntrack = true;
            break;
        default:
            printk("Unknown conntrack entry type. Drop.\n");
            return XDP_DROP;
        }
    } else {
        // First packet in a new flow...
        printk("Conntrack miss.\n");

        // TODO Check workload is allowed to use that source address.

        // TODO Look up destination in the NAT map.  If found, do DNAT.

//        struct calico_nat_v4_key nat_v4_key;
//        __builtin_memcpy(nat_v4_key.addr, &ipv4_hdr->daddr, sizeof(nat_v4_key.addr));
//        nat_v4_key.port = dest_port;
//
//        struct calico_nat_v4_value *nat_value;
//        nat_value = map_lookup_elem(&calico_nat_map_v4, &nat_v4_key);
//        if (nat_value) {
//            // Destination is to be NATted.  Calculate the backend to use...
//            struct calico_nat_secondary_v4_key secondary_key;
//            secondary_key.id = nat_value->id;
//            uint32_t r = get_prandom_u32();
//            secondary_key.ordinal = r % nat_value->count;
//
//            // Look up its IP/port.
//            struct calico_nat_secondary_v4_value *secondary_val;
//            secondary_val = map_lookup_elem(&calico_nat_secondary_map_v4, &secondary_key);
//            if (secondary_val) {
//                // Update the dest IP in the packet.
//                __builtin_memcpy(&ipv4_hdr->daddr, &secondary_val->addr, sizeof(nat_v4_key.addr));
//
//                // FIXME: update dest port
//                // FIXME: Need to adjust the checksum using bpf_csum_diff
//            } else {
//                // TODO Map must be being updated?
//                return XDP_DROP;
//            }
//        }



        // Look up (possibly new dest IP in routing table, see if it's a local workload).
        int *iface_id;
        iface_id = map_lookup_elem(&calico_local_ep_map_v4, &ipv4_hdr->daddr);
        if (iface_id) {
            printk("Found routing entry: %d.\n", *iface_id);
        }

        // TODO Execute policy.


    int result = redirect(1240, 0);
    printk("Redirect result %d\n", result);
    return result;

//        // FIXME Policy should do this tail call
//        tail_call(xdp, &calico_programs_map, CALI_PROG_ID_VETH_POST_POLICY);
//        printk("Tail call failed.\n");
//        return XDP_DROP;
    }

    printk("End of veth_main.\n");
    return XDP_DROP;
};


static __always_inline int veth_post_policy(struct xdp_md *xdp)
{
    printk("Entering veth_post_policy\n");
    printk("Test redirect....\n");
    int result = redirect(1240, 0);
    printk("Redirect result %d\n", result);
    return result;
};
//
//__section("veth_main")
//int xdp_veth_main(struct xdp_md *xdp)
//{
//	return veth_main(xdp);
//}
//
//int veth_redir(struct xdp_md *xdp)
//{
//	return redirect_map(&calico_ifaces_map, 0, 0);
//}
//
//__section("veth_redirect")
//int xdp_veth_redirect(struct xdp_md *xdp)
//{
//	return veth_redir(xdp);
//}
//
//__section("veth_post_policy")
//int xdp_veth_post_policy(struct xdp_md *xdp)
//{
//	return veth_post_policy(xdp);
//}

__section("allow_all")
int xdp_dummy(struct xdp_md *xdp)
{
	return XDP_PASS;
}

__section("drop_all")
int xdp_dummy(struct xdp_md *xdp)
{
	return XDP_DROP;
}

char __license[] __section("license") = "GPL";
