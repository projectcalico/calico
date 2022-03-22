// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __SKB_H__
#define __SKB_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "bpf.h"
#include "types.h"
#include "log.h"

#define IPV4_UDP_SIZE		(sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_IPV4_UDP_SIZE	(sizeof(struct ethhdr) + IPV4_UDP_SIZE)

#define ETH_SIZE (sizeof(struct ethhdr))
#define IP_SIZE (sizeof(struct iphdr))
#define IPv4_SIZE (sizeof(struct iphdr))
#define UDP_SIZE (sizeof(struct udphdr))
#define TCP_SIZE (sizeof(struct tcphdr))
#define ICMP_SIZE (sizeof(struct icmphdr))

/* skb_start_ptr is equivalent to (void*)((__u64)skb->data); the read is done
 * in a way that is acceptable to the verifier and it is done as a volatile read
 * ensuring that a fresh value is returned and the compiler cannot
 * reorder/recalculate the value later.
 */
static CALI_BPF_INLINE void *skb_start_ptr(struct __sk_buff *skb) {
	void *ptr;
	asm volatile (\
		"%[ptr] = *(u32 *)(%[skb] + %[offset])" \
		: [ptr] "=r" (ptr) /*out*/ \
		: [skb] "r" (skb),
		  [offset] "i" (offsetof(struct __sk_buff, data)) /*in*/ \
		: /*clobber*/ \
	);
	return ptr;
}

/* skb_end_ptr is equivalent to (void*)((__u64)skb->data_end); the read is done
 * in a way that is acceptable to the verifier and it is done as a volatile read
 * ensuring that a fresh value is returned and the compiler cannot
 * reorder/recalculate the value later.
 */
static CALI_BPF_INLINE void *skb_end_ptr(struct __sk_buff *skb) {
 	void *ptr;
 	asm volatile (\
		"%[ptr] = *(u32 *)(%[skb] + %[offset])" \
		: [ptr] "=r" (ptr) /*out*/ \
		: [skb] "r" (skb),
		  [offset] "i" (offsetof(struct __sk_buff, data_end)) /*in*/ \
		: /*clobber*/ \
	 );
	return ptr;
}

/* skb_refresh_start_end refreshes the data_start and data_end pointers in the context.
 * Fresh values are loaded using skb_start/end_ptr.
 */
static CALI_BPF_INLINE void skb_refresh_start_end(struct cali_tc_ctx *ctx) {
	if (CALI_F_XDP) {
		ctx->data_start = (void *)(long)ctx->xdp->data;
		ctx->data_end = (void *)(long)ctx->xdp->data_end;
	} else {
		ctx->data_start = skb_start_ptr(ctx->skb);
		ctx->data_end = skb_end_ptr(ctx->skb);
	}
}

/* skb_iphdr_offset returns the expected offset of the IP header for this type of program.
 * For example, in programs attached to L3 tunnel devices, the IP header is at location 0.
 * Whereas, in L2 programs, it's past the ethernet header.
 */
static CALI_BPF_INLINE long skb_iphdr_offset(void)
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

/* skb_refresh_hdr_ptrs refreshes the ip_header/nh fields in the context.
 */
static CALI_BPF_INLINE void skb_refresh_hdr_ptrs(struct cali_tc_ctx *ctx)
{
	ctx->ip_header = ctx->data_start + skb_iphdr_offset();
	ctx->nh = ctx->ip_header + IPv4_SIZE;
	CALI_DEBUG("IP id=%d s=%x d=%x\n", bpf_ntohs(ipv4hdr(ctx)->id),
			bpf_ntohl(ipv4hdr(ctx)->saddr), bpf_ntohl(ipv4hdr(ctx)->daddr));
}

/* skb_refresh_validate_ptrs refreshes the packet pointers in the context and validates access
 * to the IP header + nh_len (next header length) bytes.  If the skb is non-linear; attempts to
 * pull in that many bytes if needed.  If the pull fails, the packet pointers can be left invalid.
 *
 * After a successful validation, returns 0 and the following pointers are valid:
 * - ctx->data_start/end
 * - ctx->eth (if this BPF program has access to the L2 header)
 * - ctx->ip_header
 * - ctx->nh/tcp_header/udp_header/icmp_header.
 */
static CALI_BPF_INLINE int skb_refresh_validate_ptrs(struct cali_tc_ctx *ctx, long nh_len) {
	int min_size = skb_iphdr_offset() + IP_SIZE;
	skb_refresh_start_end(ctx);
	if (ctx->data_start + (min_size + nh_len) > ctx->data_end) {
		// This is an XDP program and there is not enough data for next header.
		if (CALI_F_XDP) {
			CALI_DEBUG("Too short to have %d bytes for next header\n",
							min_size + nh_len);
			return -2;
		}

		// Try to pull in more data.  Ideally enough for TCP, or, failing that, the
		// minimum we've been asked for.
		if (nh_len > TCP_SIZE || bpf_skb_pull_data(ctx->skb, min_size + TCP_SIZE)) {
			CALI_DEBUG("Pulling %d bytes.\n", min_size + nh_len);
			if (bpf_skb_pull_data(ctx->skb, min_size + nh_len)) {
				CALI_DEBUG("Pull failed (min len)\n");
				return -1;
			}
		}
		CALI_DEBUG("Pulled data\n");
		skb_refresh_start_end(ctx);
		if (ctx->data_start + (min_size + nh_len) > ctx->data_end) {
			return -2;
		}
	}
	// Success, refresh the IP header and next header.
	skb_refresh_hdr_ptrs(ctx);
	return 0;
}

#define skb_ptr_after(skb, ptr) ((void *)((ptr) + 1))
#define skb_seen(skb) (((skb)->mark & CALI_SKB_MARK_SEEN_MASK) == CALI_SKB_MARK_SEEN)

static CALI_BPF_INLINE long skb_l4hdr_offset(struct __sk_buff *skb, __u8 ihl)
{
	return skb_iphdr_offset() + ihl;
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
