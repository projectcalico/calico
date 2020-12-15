// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __SKB_H__
#define __SKB_H__


#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "bpf.h"
#include "types.h"
#include "log.h"

//#define skb_start_ptr(skb) ((void *)(long)(skb)->data)
//#define skb_end_ptr(skb) ((void *)(long)(skb)->data_end)

static CALI_BPF_INLINE void *skb_start_ptr(struct __sk_buff *skb) {
	void *ptr;
	asm volatile (\
		"%0 = *(u32 *)(%1 + 76)" \
		: "=r" (ptr) /*out*/ \
		: "r" (skb) /*in*/ \
		: /*clobber*/ \
	);
	return ptr;
}

static CALI_BPF_INLINE void *skb_end_ptr(struct __sk_buff *skb) {
 	void *ptr;
 	asm volatile (\
	 	"%0 = *(u32 *)(%1 + 80)" \
	 	: "=r" (ptr) /*out*/ \
	 	: "r" (skb) /*in*/ \
	 	: /*clobber*/ \
	 );
	return ptr;
}

static CALI_BPF_INLINE void skb_refresh_ptrs(struct cali_tc_ctx *ctx) {
	ctx->data_start = skb_start_ptr(ctx->skb);
	ctx->data_end = skb_end_ptr(ctx->skb);
}

#define IPV4_UDP_SIZE		(sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_IPV4_UDP_SIZE	(sizeof(struct ethhdr) + IPV4_UDP_SIZE)

#define ETH_SIZE (sizeof(struct ethhdr))
#define IP_SIZE (sizeof(struct iphdr))
#define UDP_SIZE (sizeof(struct udphdr))
#define TCP_SIZE (sizeof(struct tcphdr))
#define ICMP_SIZE (sizeof(struct icmphdr))

static CALI_BPF_INLINE bool skb_validate_ptrs(struct cali_tc_ctx *ctx, long nh_len) {
	int min_size;
	if (CALI_F_IPIP_ENCAPPED) {
		// This program sees [ eth | IP | IP | next header ]
		min_size = ETH_SIZE + IP_SIZE * 2;
	} else if (CALI_F_L3) {
		// This program sees [ IP | next header ]
		min_size = IP_SIZE;
	} else {
		// This program sees [ eth | IP | next header ]
		min_size = ETH_SIZE + IP_SIZE;
	}
	if (ctx->data_start + (min_size + nh_len) > ctx->data_end) {
		// Try to pull in more data.  Ideally enough for TCP, or, failing that, the
		// minimum we've been asked for.
		if (bpf_skb_pull_data(ctx->skb, min_size + TCP_SIZE)) {
			CALI_DEBUG("Pull failed (TCP len)\n");
			if (bpf_skb_pull_data(ctx->skb, min_size + nh_len)) {
				CALI_DEBUG("Pull failed (min len)\n");
				return true;
			}
		}
		CALI_DEBUG("Pulled data\n");
		skb_refresh_ptrs(ctx);
		return ctx->data_start + (min_size + nh_len) > ctx->data_end;
	}
	return false;
}

//#define skb_shorter(skb, len) (skb_start_ptr(skb) + (len) > skb_end_ptr(skb))
//#define skb_offset(skb, ptr) ((void*)(ptr) - skb_start_ptr(skb))
//#define skb_has_data_after(skb, ptr, size) (!skb_shorter(skb, skb_offset(skb, ptr) + \
//					     sizeof(*ptr) + (size)))
//#define skb_tail_len(skb, ptr) (skb_end_ptr(skb) - (void*)ptr)
//#define skb_ptr(skb, off) (skb_start_ptr(skb) + (off))
//
//#define skb_len_dir_access(skb) skb_tail_len(skb, skb_start_ptr(skb))

#define skb_ptr_after(skb, ptr) ((void *)((ptr) + 1))
#define skb_seen(skb) ((skb)->mark & CALI_SKB_MARK_SEEN)

static CALI_BPF_INLINE long skb_iphdr_offset(struct __sk_buff *skb)
{
	if (CALI_F_IPIP_ENCAPPED) {
		// Ingress on an IPIP tunnel: skb is [ether|outer IP|inner IP|payload]
		return sizeof(struct ethhdr) + sizeof(struct iphdr);
	} else if (CALI_F_L3) {
		// Egress on an IPIP tunnel, or Wireguard both directions:
		// skb is [inner IP|payload]
		return 0;
	} else {
		// Normal L2 interface: skb is [ether|IP|payload]
		return sizeof(struct ethhdr);
	}
}


static CALI_BPF_INLINE void skb_refresh_iphdr(struct cali_tc_ctx *ctx)
{
	long offset = skb_iphdr_offset(ctx->skb);
	struct iphdr *ip =  ctx->data_start + offset;
	CALI_DEBUG("IP id=%d s=%x d=%x\n",
			bpf_ntohs(ip->id), bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));
	ctx->ip_header = ip;
}

static CALI_BPF_INLINE long skb_l4hdr_offset(struct __sk_buff *skb, __u8 ihl)
{
	return skb_iphdr_offset(skb) + ihl;
}

static CALI_BPF_INLINE __u32 skb_ingress_ifindex(struct __sk_buff *skb)
{
#ifdef UNITTEST
	/* ingress_ifindex is not set in PROG_RUN */
	return skb->ingress_ifindex ? : skb->ifindex;
#else
	return skb->ingress_ifindex;
#endif
}

#define skb_is_gso(skb) ((skb)->gso_segs > 1)

#endif /* __SKB_H__ */
