// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "nat.h"
#include "icmp.h"
#include "parsing.h"

const volatile struct cali_tc_preamble_globals __globals;

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return TC_ACT_SHOT;
	}

	/* Set the globals for the rest of the prog chain. */
	globals->data = __globals.v6;
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;
	if (!ctx->counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	if (parse_packet_ip(ctx) != PARSING_OK_V6) {
		CALI_DEBUG("Not IPv6 packet\n");
		return TC_ACT_SHOT;
	}

	return icmp_reply(ctx, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);
}
