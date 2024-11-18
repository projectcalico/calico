// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ICMP6_H__
#define __CALI_ICMP6_H__

static CALI_BPF_INLINE int icmp_v6_reply(struct cali_tc_ctx *ctx,
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

	ipv6_addr_t orig_src;
	ipv6hdr_ip_to_ipv6_addr_t(&orig_src, &ip_hdr(ctx)->saddr);

	/* Trim the packet to the desired length. ICMPv6 requires to keep as
	 * much of the packet as fits in the minimal guaranteed MTU.
	 *
	 * RFC-2460, RFC-4443, min ipv6 MTU and we are going to add a simple
	 * ipv6 header and icmpv6 header.
	 */
	__u32 len = ctx->skb->len;
	if (len < IP_SIZE + ICMP_SIZE) {
		return -1; /* just to make verifier happy */
	}

	__u32 max = 1280 - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr);
	if (! CALI_F_L3_DEV) {
		max += ETH_SIZE;
	}

	if (len > max) {
		len = max;
		CALI_DEBUG("Trimming to %d", len);
		int err = bpf_skb_change_tail(ctx->skb, len,  0);
		if (err) {
			CALI_DEBUG("ICMP v6 reply: early bpf_skb_change_tail (len=%d) failed (err=%d)", len, err);
			return -1;
		}
	}

	/* make room for the new IP + ICMP header */
	int new_hdrs_len = sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr);
	CALI_DEBUG("Inserting %d", new_hdrs_len);
	ret = bpf_skb_adjust_room(ctx->skb, new_hdrs_len, BPF_ADJ_ROOM_MAC, 0);
	if (ret) {
		CALI_DEBUG("ICMP v6 reply: failed to make room");
		return -1;
	}

	len += new_hdrs_len;
	CALI_DEBUG("Len after insert %d", len);

	if (skb_refresh_validate_ptrs(ctx, (CALI_F_L3 ? 0 : ETH_SIZE) + IP_SIZE + ICMP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("ICMP v6 reply: too short after making room");
		return -1;
	}

	/* we do not touch ethhdr, we rely on linux to rewrite it after routing
	 * XXX we might want to swap MACs and bounce it back from the same device
	 */
	ip_hdr(ctx)->version = 6;
	ip_hdr(ctx)->hop_limit = 255; /* good default */
	ip_hdr(ctx)->nexthdr = IPPROTO_ICMPV6;
	ip_hdr(ctx)->payload_len = bpf_htons(len - IP_SIZE - (CALI_F_L3 ? 0 : ETH_SIZE));

	ctx->ipheader_len = IP_SIZE;

	/* use the host IP of the program that handles the packet */
	ipv6_addr_t_to_ipv6hdr_ip(&ip_hdr(ctx)->saddr, (ipv6_addr_t *)&INTF_IP);
	ipv6_addr_t_to_ipv6hdr_ip(&ip_hdr(ctx)->daddr, &orig_src);

	struct icmp6hdr *icmp = ((void *)ip_hdr(ctx)) + IP_SIZE;

	icmp->icmp6_type = type;
	icmp->icmp6_code = code;
	icmp->icmp6_dataun.un_data32[0] = un;
	icmp->icmp6_cksum = 0;

	__wsum icmp_csum = 0;
	__u32 data[128/4];
	int i;
	__u32 off = (CALI_F_L3 ? 0 : ETH_SIZE) + IP_SIZE;

	for (i = 0; i < 10 && off < len; i++) {
		int sz = 128;
		if (off + sz >= len) {
			sz = len - off;
			__builtin_memset(data, 0, sizeof(data));
		}
		if (sz > 128) {
			sz = 128;
		}
		if (sz <= 0) {
			return -1;
		}
		if (bpf_skb_load_bytes(ctx->skb, off, data, sz)) {
			CALI_DEBUG("icmp v6 reply: packet too short");
			return -1;
		}

		/* csum the whole buffer, it is padded with zeroes */
		icmp_csum = bpf_csum_diff(0, 0, data, 128, icmp_csum);
		off += sz;
	}

	ret = bpf_l4_csum_replace(ctx->skb,  (CALI_F_L3 ? 0 : ETH_SIZE) + IP_SIZE +
					offsetof(struct icmp6hdr, icmp6_cksum), 0, icmp_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v6 reply: set icmp csum failed");
		return -1;
	}

	/* we need to make verifier happy again */
	if (skb_refresh_validate_ptrs(ctx, (CALI_F_L3 ? 0 : ETH_SIZE) + IP_SIZE + ICMP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("ICMP v6 reply: too short after making room");
		return -1;
	}

	icmp_csum = bpf_csum_diff(0, 0, (__u32 *)&ip_hdr(ctx)->saddr, 16 + 16, 0);

	__u32 pseudo[2];
	pseudo[0] = bpf_htonl(len - (CALI_F_L3 ? 0 : ETH_SIZE) - IP_SIZE);
	pseudo[1] = bpf_htonl(IPPROTO_ICMPV6);
	icmp_csum = bpf_csum_diff(0, 0, pseudo, sizeof(pseudo), icmp_csum);

	ret = bpf_l4_csum_replace(ctx->skb,  (CALI_F_L3 ? 0 : ETH_SIZE) + IP_SIZE +
					offsetof(struct icmp6hdr, icmp6_cksum), 0, icmp_csum, BPF_F_PSEUDO_HDR);
	if (ret) {
		CALI_DEBUG("ICMP v6 reply: set icmp csum failed");
		return -1;
	}

	CALI_DEBUG("ICMP v6 reply creation succeeded");

	return 0;
}

static CALI_BPF_INLINE bool icmp_type_is_err(__u8 type) {
	return type < 128;
}

#endif /* __CALI_ICMP6_H__ */
