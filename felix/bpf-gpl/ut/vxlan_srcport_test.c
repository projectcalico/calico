// Project Calico BPF dataplane programs.
// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "nat.h"
#include "skb.h"

const volatile struct cali_tc_preamble_globals __globals;

/* Exercise the production source-port selector with packet-derived ports
 * and the configured TC globals.
 */
static CALI_BPF_INLINE int calico_unittest_entry(struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return -1;
	}

	/* Make the macros work: tc.c reads them through globals->data. */
	globals->data = __globals.v4;

	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;
	if (!ctx->counters) {
		return -1;
	}

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		return -1;
	}

	if (bpf_skb_load_bytes(skb, skb_l4hdr_offset(ctx), ctx->scratch->l4, UDP_SIZE)) {
		CALI_DEBUG("Failed to load UDP header");
		return -1;
	}

	struct udphdr *udp = udp_hdr(ctx);
	STATE->sport = bpf_ntohs(udp->source);
	STATE->dport = bpf_ntohs(udp->dest);

	return vxlan_select_src_port(ctx);
}
