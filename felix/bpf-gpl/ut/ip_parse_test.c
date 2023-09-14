// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "parsing.h"
#include "jump.h"
#include "nat.h"

const volatile struct cali_tc_globals __globals;

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return TC_ACT_SHOT;
	}

	/* Set the globals for the rest of the prog chain. */
	*globals = __globals;
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;

	if (!ctx->counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	int ver;

	switch (parse_packet_ip(ctx)) {
#ifdef IPVER6
	case PARSING_OK_V6:
		ver = 6;
		break;
#else
	case PARSING_OK:
		ver = 4;
		break;
#endif
	default:
		return TC_ACT_UNSPEC;
	}

	tc_state_fill_from_iphdr(ctx);

	switch (tc_state_fill_from_nexthdr(ctx, true)) {
	case PARSING_ERROR:
		return -1;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		return -2;
	}

	return ver;
}
