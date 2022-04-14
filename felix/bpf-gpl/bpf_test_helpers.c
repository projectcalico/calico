// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/types.h>
#include "bpf_helpers.h"
#include "bpf.h"

static CALI_BPF_INLINE void check_mtu (struct __sk_buff *skb) {
	__u32 mtu_len = 1500;
	bpf_check_mtu(skb, 0, &mtu_len, 0, 0);
}

SEC("classifier/tc/test")
int calico_tc_test_entrypoint(struct __sk_buff *skb)
{
#ifdef CALI_BPF_CHECK_MTU
	check_mtu(skb);
#endif
	return 0;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
