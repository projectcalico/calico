// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "nat.h"
#include "icmp.h"
#include "parsing.h"
#include "jump.h"

const volatile struct cali_tc_preamble_globals __globals;

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return TC_ACT_SHOT;
	}

	/* Set the globals for the rest of the prog chain. */
	globals->data = __globals.v4;
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;
	if (!ctx->counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	if (parse_packet_ip(ctx) != PARSING_OK) {
		return TC_ACT_UNSPEC;
	}

	tc_state_fill_from_iphdr(ctx);

	switch (tc_state_fill_from_nexthdr(ctx, true)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	struct {
		__be16  unused;
		__be16  mtu;
	} frag = {
		.mtu = bpf_htons(TUNNEL_MTU),
	};

	return icmp_v4_reply(ctx, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, *(__be32 *)&frag);

allow:
	return TC_ACT_UNSPEC;

deny:
	return TC_ACT_SHOT;
}

