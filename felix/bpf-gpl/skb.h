// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
#if CALI_F_XDP
	ctx->data_start = (void *)(long)ctx->xdp->data;
	ctx->data_end = (void *)(long)ctx->xdp->data_end;
#else
	ctx->data_start = skb_start_ptr(ctx->skb);
	ctx->data_end = skb_end_ptr(ctx->skb);
#endif
}

/* skb_iphdr_offset returns the expected offset of the IP header for this type of program.
 * For example, in programs attached to L3 tunnel devices, the IP header is at location 0.
 * Whereas, in L2 programs, it's past the ethernet header.
 */
static CALI_BPF_INLINE long skb_iphdr_offset(struct cali_tc_ctx *ctx)
{
	if (CALI_F_IPIP_ENCAPPED) {
		// Ingress on an IPIP tunnel: skb is [ether|outer IP|inner IP|payload]
		// TODO: we need to consider different types of IPIP tunnels like 4in6 or 6in4
		// XXX no support for ip options in ipip header
		return sizeof(struct ethhdr) + IP_SIZE;
	} else if (CALI_F_L3) {
		// Egress on an IPIP tunnel, or any other l3 devices (wireguard) both directions:
		// skb is [inner IP|payload]
		return 0;
	} else {
		// Normal L2 interface: skb is [ether|IP|payload]
		return sizeof(struct ethhdr);
	}
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
static CALI_BPF_INLINE int skb_refresh_validate_ptrs(struct cali_tc_ctx *ctx, long nh_len)
{
	int min_size = skb_iphdr_offset(ctx) + IP_SIZE;
	skb_refresh_start_end(ctx);
	if (ctx->data_start + (min_size + nh_len) > ctx->data_end) {
		// This is an XDP program and there is not enough data for next header.
#if CALI_F_XDP
		CALI_DEBUG("Too short to have %d bytes for next header",
						min_size + nh_len);
		return -2;
#else
		// Try to pull in more data.  Ideally enough for TCP, or, failing that, the
		// minimum we've been asked for.
		if (nh_len > TCP_SIZE || bpf_skb_pull_data(ctx->skb, min_size + TCP_SIZE)) {
			CALI_DEBUG("Pulling %d bytes.", min_size + nh_len);
			if (bpf_skb_pull_data(ctx->skb, min_size + nh_len)) {
				CALI_DEBUG("Pull failed (min len)");
				return -1;
			}
		}
		CALI_DEBUG("Pulled data");
		skb_refresh_start_end(ctx);
		if (ctx->data_start + (min_size + nh_len) > ctx->data_end) {
			return -2;
		}
#endif
	}
	// Success, refresh the ip_header/nh fields in the context.
	ctx->ip_header =  ctx->data_start + skb_iphdr_offset(ctx);

	return 0;
}

#define skb_ptr_after(skb, ptr) ((void *)((ptr) + 1))
#define skb_seen(skb) (((skb)->mark & CALI_SKB_MARK_SEEN_MASK) == CALI_SKB_MARK_SEEN)

#define skb_from_host(skb) (CALI_F_TO_HEP && !skb_seen(skb))

static CALI_BPF_INLINE long skb_l4hdr_offset(struct cali_tc_ctx *ctx)
{
	return skb_iphdr_offset(ctx) + ctx->ipheader_len;
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

static CALI_BPF_INLINE bool skb_is_gso(struct __sk_buff *skb) {
#ifdef BPF_CORE_SUPPORTED
	if (bpf_core_field_exists(skb->gso_size)) {
		return (skb->gso_size > 0);
	}
#endif
	return (skb->gso_segs > 1);
}

static CALI_BPF_INLINE void skb_set_mark(struct __sk_buff *skb, __u32 mark)
{
	asm volatile (\
		"*(u32 *)(%[skb] + %[offset]) = %[mark]" \
		: /*out*/ : [skb] "r" (skb), [mark] "r" (mark),
		  [offset] "i" (offsetof(struct __sk_buff, mark)) /*in*/ \
		: /*clobber*/ \
	);
}

#define skb_mark_equals(skb, mask, val) (((skb)->mark & (mask)) == (val))

#endif /* __SKB_H__ */
