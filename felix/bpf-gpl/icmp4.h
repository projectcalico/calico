// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ICMP4_H__
#define __CALI_ICMP4_H__

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
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("ICMP v4 reply: too short");
		return -1;
	}

	struct iphdr ip_orig = *ip_hdr(ctx);

	/* Trim the packet to the desired length. ICMP requires min 8 bytes of
	 * payload but the SKB implementation gets upset if we try to trim
	 * part-way through the UDP/TCP header.
	 */
	__u32 len = skb_iphdr_offset(ctx) + 60 /* max IP len */;
	switch (ip_hdr(ctx)->protocol) {
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

	CALI_DEBUG("Trimming to %d", len);
	int err = bpf_skb_change_tail(ctx->skb, len,  0);
	if (err) {
		CALI_DEBUG("ICMP v4 reply: early bpf_skb_change_tail (len=%d) failed (err=%d)", len, err);
		return -1;
	}

	/* make room for the new IP + ICMP header */
	int new_hdrs_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
	CALI_DEBUG("Inserting %d", new_hdrs_len);
	ret = bpf_skb_adjust_room(ctx->skb, new_hdrs_len, BPF_ADJ_ROOM_MAC, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: failed to make room");
		return -1;
	}

	len += new_hdrs_len;
	CALI_DEBUG("Len after insert %d", len);

	/* ICMP reply carries the IP header + at least 8 bytes of data. */
	if (skb_refresh_validate_ptrs(ctx, len - IP_SIZE - (CALI_F_L3 ? 0 : ETH_SIZE))) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("ICMP v4 reply: too short after making room");
		return -1;
	}

	/* we do not touch ethhdr, we rely on linux to rewrite it after routing
	 * XXX we might want to swap MACs and bounce it back from the same device
	 */
	ip_hdr(ctx)->version = 4;
	ip_hdr(ctx)->ihl = 5;
	ip_hdr(ctx)->tos = 0;
	ip_hdr(ctx)->ttl = 64; /* good default */
	ip_hdr(ctx)->protocol = IPPROTO_ICMP;
	ip_hdr(ctx)->check = 0;
	ip_hdr(ctx)->tot_len = bpf_htons(len - (CALI_F_L3_DEV ? 0 : ETH_SIZE));

	ctx->ipheader_len = 20;

#ifdef CALI_PARANOID
	/* XXX verify that ip_orig.daddr is always the node's IP
	 *
	 * we only call this function because of NodePort encap
	 */
	if (ip_orig.daddr != HOST_IP) {
		CALI_DEBUG("ICMP v4 reply: ip_orig.daddr != HOST_IP 0x%x", ip_orig.daddr);
	}
#endif

	/* use the host IP of the program that handles the packet */
	ip_hdr(ctx)->saddr = INTF_IP;
	ip_hdr(ctx)->daddr = ip_orig.saddr;

	struct icmphdr *icmp = ((void *)ip_hdr(ctx)) + IP_SIZE;

	icmp->type = type;
	icmp->code = code;
	*((__be32 *)&icmp->un) = un;
	icmp->checksum = 0;

	__wsum ip_csum = bpf_csum_diff(0, 0, ctx->ip_header, sizeof(struct iphdr), 0);
	__wsum icmp_csum = bpf_csum_diff(0, 0, (__u32 *)icmp,
		len - sizeof(struct iphdr) - skb_iphdr_offset(ctx), 0);
	CALI_DEBUG("ICMP: checksum 0x%x len %d", icmp_csum, len - sizeof(struct iphdr) - skb_iphdr_offset(ctx));

	ret = bpf_l3_csum_replace(ctx->skb,
			skb_iphdr_offset(ctx) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set ip csum failed");
		return -1;
	}
	ret = bpf_l4_csum_replace(ctx->skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
					offsetof(struct icmphdr, checksum), 0, icmp_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set icmp csum failed");
		return -1;
	}

	CALI_DEBUG("ICMP v4 reply creation succeeded");

	return 0;
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

#endif /* __CALI_ICMP4_H__ */
