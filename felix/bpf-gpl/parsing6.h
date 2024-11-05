// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PARSING6_H__
#define __CALI_PARSING6_H__

#include "bpf.h"

static CALI_BPF_INLINE int parse_packet_ip_v6(struct cali_tc_ctx *ctx) {
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
		CALI_DEBUG("Too short");
		goto deny;
	}
	protocol = bpf_ntohs(eth_hdr(ctx)->h_proto);
#else
	protocol = bpf_ntohs(ctx->skb->protocol);
#endif

	switch (protocol) {
	case ETH_P_IPV6:
		break;
        case ETH_P_ARP:
                CALI_DEBUG("ARP: allowing packet");
                goto allow_no_fib;
	case ETH_P_IP:
		if (CALI_F_HEP) {
			CALI_DEBUG("IPv4 on host interface: allow");
			goto allow_no_fib;
		}
		CALI_DEBUG("Unexpected ipv4 packet, drop");
		goto deny;
	default:
		if (CALI_F_WEP) {
			CALI_DEBUG("Unknown ethertype (%x), drop", protocol);
			goto deny;
		} else {
			CALI_DEBUG("Unknown ethertype on host interface (%x), allow",
									protocol);
			goto allow_no_fib;
		}
	}

	// In TC programs, parse packet and validate its size. This is
	// already done for XDP programs at the beginning of the function.
	if (!CALI_F_XDP) {
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short");
			goto deny;
		}
	}

	return PARSING_OK_V6;

allow_no_fib:
	return PARSING_ALLOW_WITHOUT_ENFORCING_POLICY;

deny:
	return PARSING_ERROR;
}

static CALI_BPF_INLINE bool ipv6_hexthdr_is_opt(int nexthdr)
{
	switch(nexthdr) {
	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_FRAGMENT:
	case NEXTHDR_GRE:
	case NEXTHDR_ESP:
	case NEXTHDR_AUTH:
	case NEXTHDR_NONE:
	case NEXTHDR_DEST:
	case NEXTHDR_MOBILITY:
		return true;
	}

	return false;
}

static CALI_BPF_INLINE void tc_state_fill_from_iphdr_v6_offset(struct cali_tc_ctx *ctx, int ipoff)
{
	// Fill in source ip
	ipv6hdr_ip_to_ipv6_addr_t(&ctx->state->ip_src, &ip_hdr(ctx)->saddr);
	// Fill in dst ip
	ipv6hdr_ip_to_ipv6_addr_t(&ctx->state->ip_dst, &ip_hdr(ctx)->daddr);
	// Fill in pre nat ip
	ctx->state->pre_nat_ip_dst = ctx->state->ip_dst;
	// Fill in other information
	ctx->state->ip_size = ip_hdr(ctx)->payload_len;

	int hdr;

	switch (ip_hdr(ctx)->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMPV6:
		ctx->ipheader_len = ctx->state->ihl = IP_SIZE;
		ctx->state->ip_proto = ip_hdr(ctx)->nexthdr;
		goto out;
	case NEXTHDR_NONE:
		goto deny;
	default:
		hdr = ip_hdr(ctx)->nexthdr;
	}

	CALI_DEBUG("ip->nexthdr %d IPv6 options!", ip_hdr(ctx)->nexthdr);

	int i;
	int len = IP_SIZE;

	for (i = 0; i < 8; i++) {
		struct ipv6_opt_hdr opt;

		CALI_DEBUG("loading extension at offset %d", ipoff + len);
		if (bpf_load_bytes(ctx, ipoff + len, &opt, sizeof(opt))) {
			CALI_DEBUG("Too short");
			goto deny;
		}

		CALI_DEBUG("ext nexthdr %d hdrlen %d", opt.nexthdr, opt.hdrlen);

		switch(hdr) {
		case NEXTHDR_FRAGMENT:
			len += 16;
			break;
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
		case NEXTHDR_GRE:
		case NEXTHDR_ESP:
		case NEXTHDR_AUTH:
		case NEXTHDR_MOBILITY:
			len += (opt.hdrlen + 1) * 8;
			break;
		}

		switch(opt.nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_ICMPV6:
				ctx->ipheader_len = ctx->state->ihl = len;
				ctx->state->ip_proto = opt.nexthdr;
				goto out;
			case NEXTHDR_NONE:
				goto deny;
		}


	}

out:
	CALI_DEBUG("IP ihl=%d bytes ip nexthdr %d", ctx->ipheader_len, ctx->state->ip_proto);
	return;

deny:
	if (CALI_F_XDP) {
		bpf_exit(XDP_DROP);
	} else {
		bpf_exit(TC_ACT_SHOT);
	}
}

static CALI_BPF_INLINE void tc_state_fill_from_iphdr_v6(struct cali_tc_ctx *ctx) {
	tc_state_fill_from_iphdr_v6_offset(ctx, skb_iphdr_offset(ctx));
}

#endif /* __CALI_PARSING6_H__ */
