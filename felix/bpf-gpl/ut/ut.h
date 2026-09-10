// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_UT_H__
#define __CALI_UT_H__

#include "bpf.h"
#include "globals.h"

/* Harness for the mini-UT programs: each test file includes this header and
 * defines calico_unittest_entry(), which the "tc" program below calls.
 */
const volatile struct cali_tc_preamble_globals __globals;

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb);

__attribute__((section("tc"))) int unittest(struct __sk_buff *skb)
{
	return calico_unittest_entry(skb);
}

#endif /* __CALI_UT_H__ */
