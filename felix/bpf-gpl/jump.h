// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_JUMP_H__
#define __CALI_BPF_JUMP_H__

#include "conntrack.h"
#include "policy.h"

CALI_MAP(cali_v5_state, 4,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, struct cali_tc_state,
		1, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE struct cali_tc_state *state_get(void)
{
	__u32 key = 0;
	return cali_v5_state_lookup_elem(&key);
}

struct bpf_map_def_extended __attribute__((section("maps"))) cali_jump2 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 16,
};

#define CALI_JUMP_TO(ctx, index) bpf_tail_call(ctx, &map_symbol(cali_jump, 2), index)

/* Add new values to the end as these are program indices */
enum cali_jump_index {
	PROG_INDEX_POLICY,
	PROG_INDEX_ALLOWED,
	PROG_INDEX_ICMP,
	PROG_INDEX_DROP,
	PROG_INDEX_HOST_CT_CONFLICT,
	PROG_INDEX_V6_PROLOGUE,
	PROG_INDEX_V6_POLICY,
	PROG_INDEX_V6_ALLOWED,
	PROG_INDEX_V6_ICMP,
	PROG_INDEX_V6_DROP,
};
#endif /* __CALI_BPF_JUMP_H__ */
