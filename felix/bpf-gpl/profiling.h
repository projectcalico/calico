// Project Calico BPF dataplane programs.
// Copyright (c) 2024 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_PROFILING_H__
#define __CALI_BPF_PROFILING_H__

struct prof_key {
	__u32 ifindex;
	__u32 kind;
};

struct prof_val {
	__u64 time;
	__u64 samples;
};

CALI_MAP(cali_profiling, 2,
		BPF_MAP_TYPE_PERCPU_HASH,
		struct prof_key, struct prof_val,
		20000, 0)

static CALI_BPF_INLINE void prof_record_sample(__u32 ifindex, __u32 kind, __u64 start, __u64 end)
{
	struct prof_key key = {
		.ifindex = ifindex,
		.kind = kind,
	};

	__u64 diff = end - start;

	struct prof_val *val = cali_profiling_lookup_elem(&key);

	if (val) {
		val->time += diff;
		val->samples++;
	} else {
		struct prof_val val = {
			.time = diff,
			.samples = 1,
		};

		cali_profiling_update_elem(&key, &val, 0);
	}
}

#endif /* __CALI_BPF_PROFILING_H__ */
