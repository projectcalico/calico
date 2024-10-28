// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_RULE_COUNTERS_H__
#define __CALI_RULE_COUNTERS_H__

#include "types.h"

CALI_MAP(cali_rule_ctrs, 2,
		BPF_MAP_TYPE_PERCPU_HASH,
		__u64, __u64, 10000, 0)

static CALI_BPF_INLINE void update_rule_counters(struct cali_tc_ctx *ctx) {
	int ret = 0;
	__u64 value = 1;
	__u64 *val = NULL;
	for (int i = 0; i < MAX_RULE_IDS; i++) {
		if (i >= ctx->state->rules_hit) {
			break;
		}
		__u64 ruleId = ctx->state->rule_ids[i];
		val = cali_rule_ctrs_lookup_elem(&ruleId);
		if (val) {
			*val = *val + 1;
		} else {
			ret = cali_rule_ctrs_update_elem(&ruleId, &value, 0);
			if (ret != 0) {
				CALI_DEBUG("error creating rule counter map entry 0x%x", ruleId);
			}
		}
	}
}

#endif /* __CALI_COUNTERS_H__ */
