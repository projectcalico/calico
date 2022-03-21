// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "skb.h"

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	struct cali_tc_ctx ctx = {
		.skb = skb,
	};

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		ctx.fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		return -1;
	}

	ip_dec_ttl(ipv4hdr(&ctx));

	return 0;
}
