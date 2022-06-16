// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "skb.h"

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	struct cali_tc_ctx ctx = {
		.counters = counters_get(),
		.skb = skb,
	};
	if (!ctx.counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		DENY_REASON(&ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		return -1;
	}

	ip_dec_ttl(ctx.ip_header);

	return 0;
}
