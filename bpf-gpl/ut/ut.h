// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "tc.c"

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb);

__attribute__((section("calico_unittest"))) int unittest(struct __sk_buff *skb)
{
	return calico_unittest_entry(skb);
}
