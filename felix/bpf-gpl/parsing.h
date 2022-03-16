// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PARSING_H__
#define __CALI_PARSING_H__

#define PARSING_OK 0
#define PARSING_OK_V6 1
#define PARSING_ALLOW_WITHOUT_ENFORCING_POLICY 2
#define PARSING_ERROR -1

#define MAX_EXTENSIONS 10

static CALI_BPF_INLINE int parse_ipv6_extensions(struct cali_tc_ctx *ctx) {
	__u8 next_header = 0;
	__u8 hdrlen = 0;
	__u16 nh_offset = skb_iphdr_offset(ctx) + 6;
	__u16 extension_offset = skb_l4hdr_offset(ctx);

	for (int i = 0; i < MAX_EXTENSIONS; i++) {
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}

		if (bpf_skb_load_bytes(ctx->skb, nh_offset, &next_header, sizeof(next_header))) {
			CALI_DEBUG("Failed to load next header\n");
			goto deny;
		}

		switch (next_header) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_ICMPV6:
				// Next header is either tcp, udp, or icmpv6. Thus pointers are correct
				goto parsing_ok;
			case IPPROTO_HOPOPTS: // Must be the first options
			case IPPROTO_ROUTING:
			case IPPROTO_FRAGMENT:
			case IPPROTO_DSTOPTS:
			case IPPROTO_MH:
				// IPv6 extension headers which we ignore at this point
				break;
			case IPPROTO_NONE:
				// There is no next header! refer to RFC8200.
				// TODO: How to handle this type of packets?
			default:
				// Any other packet that we don't expect to reach here.
				goto deny;
		}
		
		nh_offset = extension_offset;
	
		if (bpf_skb_load_bytes(ctx->skb, nh_offset + 1, &hdrlen, sizeof(hdrlen))) {
			CALI_DEBUG("Failed to load header length\n");
			goto deny;
		}

		//extension_offset += hdrlen * 8 + 8;
		ctx->iphdr_len+= hdrlen * 8 + 8;
	}

	CALI_DEBUG("Too many IPv6 extension headers");
deny:
	return PARSING_ERROR;

parsing_ok:
	//ctx->nh = ctx->data_start + extension_offset;
	return next_header;
}

static CALI_BPF_INLINE int parse_packet_ipv6(struct cali_tc_ctx *ctx) {
	switch (parse_ipv6_extensions(ctx)) {
	case IPPROTO_UDP:
		CALI_DEBUG("UDP");
		break;
	case IPPROTO_TCP:
		CALI_DEBUG("TCP");
		break;
	case IPPROTO_ICMPV6:
		CALI_DEBUG("ICMPv6");
		break;
	default:
		CALI_DEBUG("Failed to parse IPv6 extensions");
		goto deny;
	}

	//`CALI_DEBUG("IPv6 s=%x d=%x\n", ipv6hdr(ctx)->saddr, ipv6hdr(ctx)->daddr);
	CALI_DEBUG("SKB: %x", ctx->data_start);
	CALI_DEBUG("ip: %x", ctx->ip_header);
	CALI_DEBUG("nh: %x", ctx->nh);
	return PARSING_OK_V6;

deny:
	return PARSING_ERROR;
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
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}
		protocol = bpf_ntohs(tc_ethhdr(ctx)->h_proto);
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
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}
	}
	CALI_DEBUG("IP id=%d s=%x d=%x\n",
			bpf_ntohs(ipv4hdr(ctx)->id), bpf_ntohl(ipv4hdr(ctx)->saddr),
			bpf_ntohl(ipv4hdr(ctx)->daddr));

	// Drop malformed IP packets
	if (ipv4hdr(ctx)->ihl < 5) {
		ctx->fwd.reason = CALI_REASON_IP_MALFORMED;
		CALI_DEBUG("Drop malformed IP packets\n");
		goto deny;
	} else if (ipv4hdr(ctx)->ihl > 5) {
		/* Drop packets with IP options from/to WEP.
		 * Also drop packets with IP options if the dest IP is not host IP
		 */
		if (CALI_F_WEP || (CALI_F_FROM_HEP && !rt_addr_is_local_host(ipv4hdr(ctx)->daddr))) {
			ctx->fwd.reason = CALI_REASON_IP_OPTIONS;
			CALI_DEBUG("Drop packets with IP options\n");
			goto deny;
		}
		CALI_DEBUG("Allow packets with IP options and dst IP = hostIP\n");
		goto allow_no_fib;
	}

	return PARSING_OK;

ipv6_packet:
	return PARSING_OK_V6;

allow_no_fib:
	return PARSING_ALLOW_WITHOUT_ENFORCING_POLICY;

deny:
	return PARSING_ERROR;
}

static CALI_BPF_INLINE void tc_state_fill_from_iphdr(struct cali_tc_ctx *ctx)
{
	ctx->state->ip_src = ipv4hdr(ctx)->saddr;
	ctx->state->ip_dst = ipv4hdr(ctx)->daddr;
	ctx->state->pre_nat_ip_dst = ipv4hdr(ctx)->daddr;
	ctx->state->ip_proto = ipv4hdr(ctx)->protocol;
	ctx->state->ip_size = ipv4hdr(ctx)->tot_len;
}

/* Continue parsing packet based on the IP protocol and fill in relevant fields
 * in the state (struct cali_tc_state). */
static CALI_BPF_INLINE int tc_state_fill_from_nexthdr(struct cali_tc_ctx *ctx)
{
	switch (ctx->state->ip_proto) {
	case IPPROTO_TCP:
		// Re-check buffer space for TCP (has larger headers than UDP).
		if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}
		ctx->state->sport = bpf_ntohs(tc_tcphdr(ctx)->source);
		ctx->state->dport = bpf_ntohs(tc_tcphdr(ctx)->dest);
		ctx->state->pre_nat_dport = ctx->state->dport;
		CALI_DEBUG("TCP; ports: s=%d d=%d\n", ctx->state->sport, ctx->state->dport);
		break;
	case IPPROTO_UDP:
		ctx->state->sport = bpf_ntohs(tc_udphdr(ctx)->source);
		ctx->state->dport = bpf_ntohs(tc_udphdr(ctx)->dest);
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
		ctx->state->icmp_type = tc_icmphdr(ctx)->type;
		ctx->state->icmp_code = tc_icmphdr(ctx)->code;

		CALI_DEBUG("ICMP; type=%d code=%d\n",
				tc_icmphdr(ctx)->type, tc_icmphdr(ctx)->code);
		break;
	case IPPROTO_IPIP:
		if (CALI_F_TUNNEL | CALI_F_WIREGUARD) {
			// IPIP should never be sent down the tunnel.
			CALI_DEBUG("IPIP traffic to/from tunnel: drop\n");
			ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
			goto deny;
		}
		if (CALI_F_FROM_HEP) {
			if (rt_addr_is_remote_host(ctx->state->ip_src)) {
				CALI_DEBUG("IPIP packet from known Calico host, allow.\n");
				goto allow;
			} else {
				CALI_DEBUG("IPIP packet from unknown source, drop.\n");
				ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
				goto deny;
			}
		} else if (CALI_F_TO_HEP && !CALI_F_TUNNEL && !CALI_F_WIREGUARD) {
			if (rt_addr_is_remote_host(ctx->state->ip_dst)) {
				CALI_DEBUG("IPIP packet to known Calico host, allow.\n");
				goto allow;
			} else {
				CALI_DEBUG("IPIP packet to unknown dest, drop.\n");
				ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
				goto deny;
			}
		}
		if (CALI_F_FROM_WEP) {
			CALI_DEBUG("IPIP traffic from workload: drop\n");
			ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
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
