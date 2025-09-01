// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_MAGLEV_H__
#define __CALI_MAGLEV_H__


static CALI_BPF_INLINE int maglev_select_backend(struct cali_tc_ctx *ctx)
{
	__u32 hash;
	// ipv46_addr_t *ip_src = &ctx->state->ip_src;
	ipv46_addr_t *ip_dst = &ctx->state->ip_dst;
	// __u16 sport = ctx->state->sport;
	__u16 dport = ctx->state->dport;
	__u8 ip_proto = ctx->state->ip_proto;

#if 0
#ifdef IPVER6
	hash = jhash_3words(ip_src->a, ip_src->b, ip_src->c, 0xDEAD);
	hash |= jhash_3words(ip_src->d, ip_dst->a, ip_dst->b, 0xBEEF);
	hash |= jhash_3words(ip_dst->c, ip_dst->d, (__u32)ip_proto, 0xC000);
#else
	hash = jhash_3words(*ip_src, sport, 0, 0xDEAD);
	hash |= jhash_3words(*ip_dst, dport, (__u32)ip_proto, 0xBEEF);
#endif /* IPVER6 */
#endif
	hash = 0;

	struct calico_ch_key ch_key;
	struct calico_nat_dest *ch_val;

	ch_key.ordinal = hash % 1009;
	ch_key.vip = *ip_dst;
	ch_key.port = dport;
	ch_key.proto = ip_proto;
	ch_val = cali_ch_lookup_elem(&ch_key);

	if (!ch_val) {
		CALI_DEBUG("Maglev: no backend found for " IP_FMT ":%d", debug_ip(*ip_dst), dport);
		return -1;
	}

	/* TODO setup nat_dest */

	return 0;
}

#endif /* __CALI_MAGLEV_H__ */
