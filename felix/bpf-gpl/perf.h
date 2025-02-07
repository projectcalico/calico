// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PERF_H__
#define __CALI_PERF_H__

#include "bpf.h"
#include "perf_types.h"

/* perf_commit_event commits an event with the provided data */
static CALI_BPF_INLINE int perf_commit_event(void *ctx, void *data, __u64 size)
{
	return bpf_perf_event_output(ctx, &cali_perf_evnt, BPF_F_CURRENT_CPU, data, size);
}

/* perf_commit_event_ctx commits an event and includes ctx_send_size bytes of the context */
static CALI_BPF_INLINE int perf_commit_event_ctx(void *ctx, __u32 ctx_send_size, void *data, __u64 size)
{
	__u64 flags = BPF_F_CURRENT_CPU | (((__u64)ctx_send_size << 32) & BPF_F_CTXLEN_MASK);

	return bpf_perf_event_output(ctx, &cali_perf_evnt, flags, data, size);
}

#endif /* __CALI_PERF_H__ */
