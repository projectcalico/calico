// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "nat.h"
#ifndef IPVER6
#include "tcp4.h"
#else
#include "tcp6.h"
#endif
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
#ifndef IPVER6
	globals->data = __globals.v4;
#else
	globals->data = __globals.v6;
#endif
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;
	if (!ctx->counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}
	int ret = PARSING_OK;
#ifdef IPVER6
	ret = PARSING_OK_V6;
#endif
	if (parse_packet_ip(ctx) != ret) {
		return TC_ACT_UNSPEC;
	}

	tc_state_fill_from_iphdr(ctx);

	switch (tc_state_fill_from_nexthdr(ctx, true)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}
#ifndef IPVER6
	return tcp_v4_rst(ctx);
#else
	return tcp_v6_rst(ctx);
#endif

allow:
	return TC_ACT_UNSPEC;

deny:
	return TC_ACT_SHOT;
}

