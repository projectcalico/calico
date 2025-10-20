// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_MAGLEV_H__
#define __CALI_MAGLEV_H__

#include "jenkins_hash.h"

static CALI_BPF_INLINE struct calico_nat_dest* maglev_select_backend(struct cali_tc_ctx *ctx)
{
	__u32 hash;
	ipv46_addr_t *ip_src = &ctx->state->ip_src;
	ipv46_addr_t *ip_dst = &ctx->state->ip_dst;
	__u16 sport = ctx->state->sport;
	__u16 dport = ctx->state->dport;
	__u8 ip_proto = ctx->state->ip_proto;
	__u32 lut_size = ctx->globals->data.maglev_lut_size;

#ifdef IPVER6
	const __u32 ip_arr[11] = {
		ip_src->a, ip_src->b, ip_src->c, ip_src->d,
		ip_dst->a, ip_dst->b, ip_dst->c, ip_dst->d,
		(__u32)ip_proto, sport, dport
	};

	hash = hashword(ip_arr, 11, 0xCA71C0);
#else
	const __u32 ip_arr[5] = {*ip_src, *ip_dst, sport, dport, (__u32) ip_proto};
	hash = hashword (ip_arr, 5, 0xCA71C0);
#endif /* IPVER6 */

	CALI_DEBUG("Maglev: hashed packet to %d", hash);
	struct cali_maglev_key ch_key = {
		.ordinal = (hash % lut_size),
		.vip = *ip_dst,
		.port = dport,
		.proto = ip_proto,
	};
	struct calico_nat_dest *ch_val;

	ch_val = cali_maglev_lookup_elem(&ch_key);

	if (!ch_val) {
		__u32 proto_debug = ip_proto;
		CALI_DEBUG("Maglev: no backend found for " IP_FMT ":%d", debug_ip(*ip_dst), dport);
		CALI_DEBUG("Packet proto: %d, Ordinal: %d", proto_debug, ch_key.ordinal);

		return NULL;
	}

	return ch_val;
}

#endif /* __CALI_MAGLEV_H__ */
