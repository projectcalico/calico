// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "nat.h"

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	struct cali_tc_ctx ctx = {
		.skb = skb,
		.iphdr_len = IPv4_SIZE,
	};
	return icmp_v4_too_big(&ctx);
}

