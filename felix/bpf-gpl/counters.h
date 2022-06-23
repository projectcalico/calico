// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_COUNTERS_H__
#define __CALI_COUNTERS_H__

#define MAX_COUNTERS_SIZE 13

typedef __u32 counters_t[MAX_COUNTERS_SIZE];

CALI_MAP(cali_counters, 1,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, counters_t, 1,
		0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE counters_t *counters_get(void)
{
	int zero = 0;
	return cali_counters_lookup_elem(&zero);
}

#define COUNTER_INC(ctx, type) ((*((ctx)->counters))[type]++)

#endif /* __CALI_COUNTERS_H__ */
