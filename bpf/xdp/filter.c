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

#include "../include/bpf.h"

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

struct lpm_v4_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct lpm_val {
	__u32 ref_count;
};

struct failsafe_key {
	__u8 proto;
	__u8 pad;
	__u16 port;
};

struct failsafe_value {
	__u8 dummy;
};

// calico_prefilter_v4 contains one entry per CIDR that should be dropped by
// the prefilter.
//
// Key: the CIDR, formatted for LPM lookup
// Value: reference count, used only by felix
struct bpf_elf_map calico_prefilter_v4 __section(ELF_SECTION_MAPS) = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.size_key       = sizeof(struct lpm_v4_key),
	.size_value     = sizeof(struct lpm_val),
	.flags          = BPF_F_NO_PREALLOC,
	.max_elem       = 512000, // arbitrary
};

// calico_failsafe_ports contains one entry per port/proto that we should NOT
// block even if there's a blacklist rule. This corresponds with the failsafe
// ports option in Felix and is populated by Felix at startup time.
//
// Key: the protocol and port
// Value: not used
struct bpf_elf_map calico_failsafe_ports __section(ELF_SECTION_MAPS) = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(struct failsafe_key),
	.size_value     = sizeof(struct failsafe_value),
	.flags          = BPF_F_NO_PREALLOC,
	.max_elem       = 65535 * 2, // number of ports for TCP and UDP
};

static __always_inline
__u16 get_dest_port_ipv4_udp(struct xdp_md *ctx, __u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct udphdr *udph;
	__u16 dport;

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
__u16 get_dest_port_ipv4_tcp(struct xdp_md *ctx, __u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct tcphdr *tcph;
	__u16 dport;

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


static __always_inline int check_v4(struct xdp_md *xdp)
{
	void *data_end = xdp_data_end(xdp);
	void *data = xdp_data(xdp);
	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
	struct lpm_v4_key pfx;
	__u16 dest_port;

	if (xdp_no_room(ipv4_hdr + 1, data_end)) {
		return XDP_DROP;
	}

	__builtin_memcpy(pfx.lpm.data, &ipv4_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 32;

	if (map_lookup_elem(&calico_prefilter_v4, &pfx)) {
		// check failsafe ports
		switch (ipv4_hdr->protocol) {
			case IPPROTO_TCP:
				dest_port = get_dest_port_ipv4_tcp(xdp, sizeof(struct ethhdr));
				break;
			case IPPROTO_UDP:
				dest_port = get_dest_port_ipv4_udp(xdp, sizeof(struct ethhdr));
				break;
			default:
				return XDP_DROP;
		}

		struct failsafe_key key = {};

		key.proto = ipv4_hdr->protocol;
		key.port = dest_port;
		if (map_lookup_elem(&calico_failsafe_ports, &key)) {
			return XDP_PASS;
		}

		// no failsafe ports matched, drop
		return XDP_DROP;
	}

	return XDP_PASS;
}


static __always_inline int check_prefilter(struct xdp_md *xdp)
{
	void *data_end = xdp_data_end(xdp);
	void *data = xdp_data(xdp);
	struct ethhdr *eth = data;
	__u16 proto;

	if (xdp_no_room(eth + 1, data_end)) {
		return XDP_DROP;
	}

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_IP)) {
		return check_v4(xdp);
	} else {
		/* other traffic can continue */
		return XDP_PASS;
	}
}

__section("pre-filter")
int xdp_enter(struct xdp_md *xdp)
{
	return check_prefilter(xdp);
}
