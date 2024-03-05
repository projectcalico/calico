// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "skb.h"

const volatile struct cali_tc_preamble_globals __globals;

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;
	if (!ctx->counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		return -1;
	}

	ip_dec_ttl(ip_hdr(ctx));

	return 0;
}
