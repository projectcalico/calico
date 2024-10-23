// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PARSING4_H__
#define __CALI_PARSING4_H__

static CALI_BPF_INLINE int parse_packet_ip_v4(struct cali_tc_ctx *ctx)
{
	__u16 protocol = 0;

	/* We need to make a decision based on Ethernet protocol, however,
	 * the protocol number is not available to XDP programs like TC ones.
	 * In TC programs protocol number is available via skb->protocol.
	 * For that, in XDP programs we need to parse at least up to Ethernet
	 * first, before making any decision. But in TC programs we can make
	 * an initial decision based on Ethernet protocol before parsing packet
	 * for more headers.
	 */
#if CALI_F_XDP
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	protocol = bpf_ntohs(eth_hdr(ctx)->h_proto);
#else
	protocol = bpf_ntohs(ctx->skb->protocol);
#endif

	switch (protocol) {
	case ETH_P_IP:
		break;
	case ETH_P_ARP:
		CALI_DEBUG("ARP: allowing packet\n");
		goto allow_no_fib;
	case ETH_P_IPV6:
		// Drop if the packet is to/from workload
		if (CALI_F_WEP) {
			CALI_DEBUG("IPv6 to/from workload: drop\n");
			goto deny;
		} else { // or allow, it the packet is on host interface
			CALI_DEBUG("IPv6 on host interface: allow\n");
			goto allow_no_fib;
		}
	default:
		if (CALI_F_WEP) {
			CALI_DEBUG("Unknown ethertype (%x), drop\n", protocol);
			goto deny;
		} else {
			CALI_DEBUG("Unknown ethertype on host interface (%x), allow\n",
									protocol);
			goto allow_no_fib;
		}
	}

	// In TC programs, parse packet and validate its size. This is
	// already done for XDP programs at the beginning of the function.
#if !CALI_F_XDP
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}
#endif

	CALI_DEBUG("IP id=%d len=%d\n",bpf_ntohs(ip_hdr(ctx)->id), bpf_htons(ip_hdr(ctx)->tot_len));
	CALI_DEBUG("IP s=" IP_FMT " d=" IP_FMT "\n", debug_ip(ip_hdr(ctx)->saddr), debug_ip(ip_hdr(ctx)->daddr));
	// Drop malformed IP packets
	if (ip_hdr(ctx)->ihl < 5) {
		CALI_DEBUG("Drop malformed IP packets\n");
		deny_reason(ctx, CALI_REASON_IP_MALFORMED);
		goto deny;
	}

	return PARSING_OK;

allow_no_fib:
	return PARSING_ALLOW_WITHOUT_ENFORCING_POLICY;

deny:
	return PARSING_ERROR;
}

static CALI_BPF_INLINE void tc_state_fill_from_iphdr_v4(struct cali_tc_ctx *ctx)
{
	ctx->state->ip_src = ip_hdr(ctx)->saddr;
	ctx->state->ip_dst = ip_hdr(ctx)->daddr;
	ctx->state->pre_nat_ip_dst = ip_hdr(ctx)->daddr;
	ctx->state->ip_proto = ip_hdr(ctx)->protocol;
	ctx->state->ip_size = ip_hdr(ctx)->tot_len;
	ctx->ipheader_len = ctx->state->ihl = ip_hdr(ctx)->ihl * 4;
	CALI_DEBUG("IP ihl=%d bytes\n", ctx->ipheader_len);
}

#endif /* __CALI_PARSING4_H__ */
