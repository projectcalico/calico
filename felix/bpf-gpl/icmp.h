// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ICMP_H__
#define __CALI_ICMP_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "bpf.h"
#include "log.h"
#include "skb.h"

static CALI_BPF_INLINE int icmp_v4_reply(struct cali_tc_ctx *ctx,
					__u8 type, __u8 code, __be32 un)
{
	int ret;

	/* ICMP is on the slow path so we may as well revalidate here to keep calling code
	 * simple.  We only need to look at the IP header before we resize the packet. */
	if (skb_refresh_validate_ptrs(ctx, 0)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		INC(ctx, ERR_SHORT_PKTS);
		CALI_DEBUG("ICMP v4 reply: too short\n");
		return -1;
	}

	struct iphdr ip_orig = *ctx->ip_header;
	CALI_DEBUG("ip->ihl: %d\n", ctx->ip_header->ihl);
	if (ctx->ip_header->ihl > 5) {
		CALI_DEBUG("ICMP v4 reply: IP options\n");
		return -1;
	}
	/* Trim the packet to the desired length. ICMP requires min 8 bytes of
	 * payload but the SKB implementation gets upset if we try to trim
	 * part-way through the UDP/TCP header.
	 */
	__u32 len = skb_iphdr_offset() + sizeof(struct iphdr) + 64;
	switch (ctx->ip_header->protocol) {
	case IPPROTO_TCP:
		len += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		len += sizeof(struct udphdr);
		break;
	default:
		len += 8;
		break;
	}

	CALI_DEBUG("Trimming to %d\n", len);
	int err = bpf_skb_change_tail(ctx->skb, len,  0);
	if (err) {
		CALI_DEBUG("ICMP v4 reply: early bpf_skb_change_tail (len=%d) failed (err=%d)\n", len, err);
		return -1;
	}
        
	/* make room for the new IP + ICMP header */
	int new_hdrs_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
	CALI_DEBUG("Inserting %d\n", new_hdrs_len);
	ret = bpf_skb_adjust_room(ctx->skb, new_hdrs_len, BPF_ADJ_ROOM_MAC, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: failed to make room\n");
		return -1;
	}

	len += new_hdrs_len;
	CALI_DEBUG("Len after insert %d\n", len);

	/* ICMP reply carries the IP header + at least 8 bytes of data. */
	if (skb_refresh_validate_ptrs(ctx, len - skb_iphdr_offset() - IP_SIZE)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		INC(ctx, ERR_SHORT_PKTS);
		CALI_DEBUG("ICMP v4 reply: too short after making room\n");
		return -1;
	}

	/* we do not touch ethhdr, we rely on linux to rewrite it after routing
	 * XXX we might want to swap MACs and bounce it back from the same device
	 */
	ctx->ip_header->version = 4;
	ctx->ip_header->ihl = 5;
	ctx->ip_header->tos = 0;
	ctx->ip_header->ttl = 64; /* good default */
	ctx->ip_header->protocol = IPPROTO_ICMP;
	ctx->ip_header->check = 0;
	ctx->ip_header->tot_len = bpf_htons(len - sizeof(struct ethhdr));

#ifdef CALI_PARANOID
	/* XXX verify that ip_orig.daddr is always the node's IP
	 *
	 * we only call this function because of NodePort encap
	 */
	if (ip_orig.daddr != HOST_IP) {
		CALI_DEBUG("ICMP v4 reply: ip_orig.daddr != HOST_IP 0x%x\n", ip_orig.daddr);
	}
#endif

	/* use the host IP of the program that handles the packet */
	ctx->ip_header->saddr = INTF_IP;
	ctx->ip_header->daddr = ip_orig.saddr;

	tc_icmphdr(ctx)->type = type;
	tc_icmphdr(ctx)->code = code;
	*((__be32 *)&tc_icmphdr(ctx)->un) = un;
	tc_icmphdr(ctx)->checksum = 0;

	__wsum ip_csum = bpf_csum_diff(0, 0, (void *)ctx->ip_header, sizeof(*ctx->ip_header), 0);
	__wsum icmp_csum = bpf_csum_diff(0, 0, ctx->nh,
		len - sizeof(struct iphdr) - skb_iphdr_offset(), 0);

	ret = bpf_l3_csum_replace(ctx->skb,
			skb_iphdr_offset() + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set ip csum failed\n");
		return -1;
	}
	ret = bpf_l4_csum_replace(ctx->skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
					offsetof(struct icmphdr, checksum), 0, icmp_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set icmp csum failed\n");
		return -1;
	}

	CALI_DEBUG("ICMP v4 reply creation succeeded\n");

	return 0;
}

static CALI_BPF_INLINE int icmp_v4_too_big(struct cali_tc_ctx *ctx)
{
	struct {
		__be16  unused;
		__be16  mtu;
	} frag = {
		.mtu = bpf_htons(TUNNEL_MTU),
	};

	CALI_DEBUG("Sending ICMP too big mtu=%d\n", bpf_ntohs(frag.mtu));
	return icmp_v4_reply(ctx, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, *(__be32 *)&frag);
}

static CALI_BPF_INLINE int icmp_v4_ttl_exceeded(struct cali_tc_ctx *ctx)
{
	return icmp_v4_reply(ctx, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
}

static CALI_BPF_INLINE int icmp_v4_port_unreachable(struct cali_tc_ctx *ctx)
{
	return icmp_v4_reply(ctx, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
}

static CALI_BPF_INLINE bool icmp_type_is_err(__u8 type)
{
	switch (type) {
	case ICMP_DEST_UNREACH:
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		return true;
	}

	return false;
}

#endif /* __CALI_ICMP_H__ */
