// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PERF_TYPES_H__
#define __CALI_PERF_TYPES_H__

#include "bpf.h"

CALI_MAP_V1(cali_perf_evnt,
		BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		__u32, __u32,
		512,
		0)

/* We need the header to be 64bit of size so that any 64bit fields in the
 * message structures that embed this header are also aligned.
 */
struct perf_event_header {
	__u32 type;
	__u32 len;
};

struct perf_event_timestamp_header {
	struct perf_event_header h;
	__u64 timestamp_ns;
};

#endif /* __CALI_PERF_TYPES_H__ */
