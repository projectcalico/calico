// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PARSING_H__
#define __CALI_PARSING_H__

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include "skb.h"
#include "routes.h"

#define PARSING_OK 0
#define PARSING_OK_V6 1
#define PARSING_ALLOW_WITHOUT_ENFORCING_POLICY 2
#define PARSING_ERROR -1

static CALI_BPF_INLINE int bpf_load_bytes(struct cali_tc_ctx *ctx, __u32 offset, void *buf, __u32 len)
{
	int ret;

	if (CALI_F_XDP) {
#ifdef BPF_CORE_SUPPORTED
		if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_xdp_load_bytes)) {
			ret = bpf_xdp_load_bytes(ctx->xdp, offset, buf, len);
		} else
#endif
		{
			return -22 /* EINVAL */;
		}
	} else {
		ret = bpf_skb_load_bytes(ctx->skb, offset, buf, len);
	}

	return ret;
}

static CALI_BPF_INLINE int parse_packet_ip(struct cali_tc_ctx *ctx) {
	__u16 protocol = 0;

	/* We need to make a decision based on Ethernet protocol, however,
	 * the protocol number is not available to XDP programs like TC ones.
	 * In TC programs protocol number is available via skb->protocol.
	 * For that, in XDP programs we need to parse at least up to Ethernet
	 * first, before making any decision. But in TC programs we can make
	 * an initial decision based on Ethernet protocol before parsing packet
	 * for more headers.
	 */
	if (CALI_F_XDP) {
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short\n");
			goto deny;
		}
		protocol = bpf_ntohs(eth_hdr(ctx)->h_proto);
	} else {
		protocol = bpf_ntohs(ctx->skb->protocol);
	}

	switch (protocol) {
	case ETH_P_IP:
		break;
	case ETH_P_ARP:
		CALI_DEBUG("ARP: allowing packet\n");
		goto allow_no_fib;
	case ETH_P_IPV6:
		// If IPv6 is supported and enabled, handle the packet
		if (GLOBAL_FLAGS & CALI_GLOBALS_IPV6_ENABLED) {
			CALI_DEBUG("IPv6 packet, continue with parsing it.\n");
			goto ipv6_packet;
		}
		// otherwise, drop if the packet is from workload
		if (CALI_F_WEP) {
			CALI_DEBUG("IPv6 from workload: drop\n");
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
	if (!CALI_F_XDP) {
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short\n");
			goto deny;
		}
	}

	CALI_DEBUG("IP id=%d\n",bpf_ntohs(ip_hdr(ctx)->id));
	CALI_DEBUG("IP s=%x d=%x\n", bpf_ntohl(ip_hdr(ctx)->saddr), bpf_ntohl(ip_hdr(ctx)->daddr));
	// Drop malformed IP packets
	if (ip_hdr(ctx)->ihl < 5) {
		CALI_DEBUG("Drop malformed IP packets\n");
		deny_reason(ctx, CALI_REASON_IP_MALFORMED);
		goto deny;
	} else if (ip_hdr(ctx)->ihl > 5) {
		/* Drop packets with IP options from/to WEP.
		 * Also drop packets with IP options if the dest IP is not host IP
		 */
		ctx->ipheader_len = 4 * ip_hdr(ctx)->ihl;
	}
	/* XXX */
	ctx->nh = ctx->scratch->l4;
	CALI_DEBUG("IP ihl=%d bytes\n", ctx->ipheader_len);

	return PARSING_OK;

ipv6_packet:
	// Parse IPv6 header, and perform necessary checks here
	return PARSING_OK_V6;

allow_no_fib:
	return PARSING_ALLOW_WITHOUT_ENFORCING_POLICY;

deny:
	return PARSING_ERROR;
}

static CALI_BPF_INLINE void tc_state_fill_from_iphdr(struct cali_tc_ctx *ctx)
{
	ctx->state->ip_src = ip_hdr(ctx)->saddr;
	ctx->state->ip_dst = ip_hdr(ctx)->daddr;
	ctx->state->pre_nat_ip_dst = ip_hdr(ctx)->daddr;
	ctx->state->ip_proto = ip_hdr(ctx)->protocol;
	ctx->state->ip_size = ip_hdr(ctx)->tot_len;
}

static CALI_BPF_INLINE void tc_state_fill_from_ipv6hdr(struct cali_tc_ctx *ctx)
{
	// Fill in source ip
	ctx->state->ip_src  = ipv6_hdr(ctx)->saddr.in6_u.u6_addr32[0];
	ctx->state->ip_src1 = ipv6_hdr(ctx)->saddr.in6_u.u6_addr32[1];
	ctx->state->ip_src2 = ipv6_hdr(ctx)->saddr.in6_u.u6_addr32[2];
	ctx->state->ip_src3 = ipv6_hdr(ctx)->saddr.in6_u.u6_addr32[3];
	// Fill in dst ip
	ctx->state->ip_dst  = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[0];
	ctx->state->ip_dst1 = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[1];
	ctx->state->ip_dst2 = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[2];
	ctx->state->ip_dst3 = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[3];
	// Fill in pre nat ip
	ctx->state->pre_nat_ip_dst  = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[0];
	ctx->state->pre_nat_ip_dst1 = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[1];
	ctx->state->pre_nat_ip_dst2 = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[2];
	ctx->state->pre_nat_ip_dst3 = ipv6_hdr(ctx)->daddr.in6_u.u6_addr32[3];
	// Fill in other information
	ctx->state->ip_proto = ipv6_hdr(ctx)->nexthdr;
	ctx->state->ip_size = ipv6_hdr(ctx)->payload_len;
}

/* Continue parsing packet based on the IP protocol and fill in relevant fields
 * in the state (struct cali_tc_state). */
static CALI_BPF_INLINE int tc_state_fill_from_nexthdr(struct cali_tc_ctx *ctx, bool decap)
{
	if (ip_hdr(ctx)->ihl == 5) {
		switch (ctx->state->ip_proto) {
		case IPPROTO_TCP:
			if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
				deny_reason(ctx, CALI_REASON_SHORT);
				CALI_DEBUG("Too short\n");
				goto deny;
			}
			__builtin_memcpy(ctx->scratch->l4, ((void*)ip_hdr(ctx))+IP_SIZE, TCP_SIZE);
			break;
		case IPPROTO_UDP:
			{
				int len = UDP_SIZE;
				if (decap) {
					/* We try to opportunistically load the vxlan
					 * header as well, small cost and makes reading
					 * vxlan cheap later.
					 */
					len += sizeof(struct vxlanhdr);
					if (skb_refresh_validate_ptrs(ctx, len) == 0) {
						__builtin_memcpy(ctx->scratch->l4, ((void*)ip_hdr(ctx))+IP_SIZE, len);
						break;
					}
				}
				if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
					deny_reason(ctx, CALI_REASON_SHORT);
					CALI_DEBUG("Too short\n");
					goto deny;
				}
				__builtin_memcpy(ctx->scratch->l4, ((void*)ip_hdr(ctx))+IP_SIZE, UDP_SIZE);
			}
			break;
		default:
			__builtin_memcpy(ctx->scratch->l4, ((void*)ip_hdr(ctx))+IP_SIZE, UDP_SIZE);
			break;
		}
	} else {
		switch (ctx->state->ip_proto) {
		case IPPROTO_TCP:
			/* Load the L4 header in case there were ip options as we loaded the options instead. */
			if (bpf_load_bytes(ctx, skb_l4hdr_offset(ctx), ctx->scratch->l4, TCP_SIZE)) {
				CALI_DEBUG("Too short\n");
				goto deny;
			}
			break;
		case IPPROTO_UDP:
			{
				int len = UDP_SIZE;
				if (decap) {
					/* We try to opportunistically load the vxlan
					 * header as well, small cost and makes reading
					 * vxlan cheap later.
					 */
					len += sizeof(struct vxlanhdr);
				}
				int offset =  skb_l4hdr_offset(ctx);
				if (bpf_load_bytes(ctx, offset, ctx->scratch->l4, len)) {
					if (bpf_load_bytes(ctx, offset, ctx->scratch->l4, UDP_SIZE)) {
						CALI_DEBUG("Too short\n");
						goto deny;
					}
				}
			}
			break;
		default:
			if (bpf_load_bytes(ctx, skb_l4hdr_offset(ctx), ctx->scratch->l4, UDP_SIZE)) {
				CALI_DEBUG("Too short\n");
				goto deny;
			}
			break;
		}
	}

	switch (ctx->state->ip_proto) {
	case IPPROTO_TCP:
		ctx->state->sport = bpf_ntohs(tcp_hdr(ctx)->source);
		ctx->state->dport = bpf_ntohs(tcp_hdr(ctx)->dest);
		ctx->state->pre_nat_dport = ctx->state->dport;
		CALI_DEBUG("TCP; ports: s=%d d=%d\n", ctx->state->sport, ctx->state->dport);
		break;
	case IPPROTO_UDP:
		ctx->state->sport = bpf_ntohs(udp_hdr(ctx)->source);
		ctx->state->dport = bpf_ntohs(udp_hdr(ctx)->dest);
		ctx->state->pre_nat_dport = ctx->state->dport;
		CALI_DEBUG("UDP; ports: s=%d d=%d\n", ctx->state->sport, ctx->state->dport);
		if (ctx->state->dport == VXLAN_PORT) {
			/* CALI_F_FROM_HEP case is handled in vxlan_attempt_decap above since it already decoded
			 * the header. */
			if (CALI_F_TO_HEP) {
				if (rt_addr_is_remote_host(ctx->state->ip_dst) &&
						rt_addr_is_local_host(ctx->state->ip_src)) {
					CALI_DEBUG("VXLAN packet to known Calico host, allow.\n");
					goto allow;
				} else {
					/* Unlike IPIP, the user can be using VXLAN on a different VNI
					 * so we don't simply drop it. */
					CALI_DEBUG("VXLAN packet to unknown dest, fall through to policy.\n");
				}
			}
		}
		break;
	case IPPROTO_ICMP:
		ctx->state->icmp_type = icmp_hdr(ctx)->type;
		ctx->state->icmp_code = icmp_hdr(ctx)->code;

		CALI_DEBUG("ICMP; type=%d code=%d\n",
				icmp_hdr(ctx)->type, icmp_hdr(ctx)->code);
		break;
	case IPPROTO_IPIP:
		if (CALI_F_TUNNEL | CALI_F_L3_DEV) {
			// IPIP should never be sent down the tunnel.
			CALI_DEBUG("IPIP traffic to/from tunnel: drop\n");
			deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
			goto deny;
		}
		if (CALI_F_FROM_HEP) {
			if (rt_addr_is_remote_host(ctx->state->ip_src)) {
				CALI_DEBUG("IPIP packet from known Calico host, allow.\n");
				goto allow;
			} else {
				CALI_DEBUG("IPIP packet from unknown source, drop.\n");
				deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
				goto deny;
			}
		} else if (CALI_F_TO_HEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV) {
			if (rt_addr_is_remote_host(ctx->state->ip_dst)) {
				CALI_DEBUG("IPIP packet to known Calico host, allow.\n");
				goto allow;
			} else {
				CALI_DEBUG("IPIP packet to unknown dest, drop.\n");
				deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
				goto deny;
			}
		}
		if (CALI_F_FROM_WEP) {
			CALI_DEBUG("IPIP traffic from workload: drop\n");
			deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
			goto deny;
		}
	default:
		CALI_DEBUG("Unknown protocol (%d), unable to extract ports\n",
					(int)ctx->state->ip_proto);
	}

	return PARSING_OK;

allow:
	return PARSING_ALLOW_WITHOUT_ENFORCING_POLICY;

deny:
	return PARSING_ERROR;
}

#endif /* __CALI_PARSING_H__ */
