// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_TCP4_H__
#define __CALI_TCP4_H__

#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf.h"
#include "log.h"
#include "skb.h"

static CALI_BPF_INLINE int tcp_v4_rst(struct cali_tc_ctx *ctx) {
	if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("TCP reset : too short");
		return -1;
	}
	struct iphdr ip_orig = *ip_hdr(ctx);
	struct tcphdr th_orig = *tcp_hdr(ctx);
	int original_len = ctx->skb->len;

	/* Trim to minimum size */
	__u32 len = skb_iphdr_offset(ctx) + IP_SIZE + TCP_SIZE /* max IP len */;
	int err = bpf_skb_change_tail(ctx->skb, len,  0);
	if (err) {
		CALI_DEBUG("tcp reset reply: bpf_skb_change_tail (len=%d) failed (err=%d)", len, err);
		return -1;
	}               

	/* Revalidate all pointers */
	if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("TCP reset : too short");
		return -1;
	}
	ip_hdr(ctx)->version = 4;
	ip_hdr(ctx)->ihl = 5;
	ip_hdr(ctx)->tos = 0;
	ip_hdr(ctx)->ttl = 64;
	ip_hdr(ctx)->protocol = IPPROTO_TCP;
	ip_hdr(ctx)->saddr = ip_orig.daddr;
	ip_hdr(ctx)->daddr = ip_orig.saddr;
	ip_hdr(ctx)->check = 0;
	ip_hdr(ctx)->tot_len = bpf_htons(len - (CALI_F_L3_DEV ? 0 : ETH_SIZE));
	ctx->ipheader_len = 20;

	struct tcphdr *th = ((void *)ip_hdr(ctx)) + IP_SIZE;
	th->source = th_orig.dest;
	th->dest = th_orig.source;
	th->rst = 1;
	th->doff = sizeof(struct tcphdr) / 4;
	th->seq = 0;

	if (th_orig.ack) {
		th->seq = th_orig.ack_seq;
	} else {
		th->ack_seq = bpf_htonl(bpf_ntohl(th_orig.seq) + th_orig.syn + th_orig.fin + 
				original_len - (th_orig.doff << 2));
		th->ack = 1;
	}
	th->check = 0;

	__wsum ip_csum = bpf_csum_diff(0, 0, ctx->ip_header, sizeof(struct iphdr), 0);
	__wsum tcp_csum = bpf_csum_diff(0, 0, (__u32 *)th, len - sizeof(struct iphdr) - skb_iphdr_offset(ctx), 0);
	if (bpf_l3_csum_replace(ctx->skb,
			skb_iphdr_offset(ctx) + offsetof(struct iphdr, check), 0, ip_csum, 0)) {
		CALI_DEBUG("TCP reset v4 reply: set ip csum failed");
		return -1;
	}


	err = bpf_l4_csum_replace(ctx->skb, skb_l4hdr_offset(ctx) +
			offsetof(struct tcphdr, check), 0, tcp_csum, BPF_F_PSEUDO_HDR);
	if (err) {
		CALI_DEBUG("TCP reset v4 reply: set tcp csum failed %d", err);
		return -1;
	}
	return 0;
}

#endif /* __CALI_TCP4_H__ */
