// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_RINGBUF_H__
#define __CALI_RINGBUF_H__

#include "bpf.h"

// Ring buffer map macro — ring buffers have no key/value types and no
// lookup/update/delete helpers. max_entries is the buffer size in bytes.
#define CALI_RINGBUF(name, size_bytes)		\
struct {					\
	__uint(type, BPF_MAP_TYPE_RINGBUF);	\
	__uint(max_entries, size_bytes);		\
} name SEC(".maps");

// Shared event ring buffer.
// The 1MB compile-time value is a fallback default. At runtime, Go overrides
// max_entries via maps.SetSize() -> bpf_map__set_max_entries() to
// BPFExportBufferSizeMB * NumCPU (preserving the same total buffer capacity
// as the old per-CPU perf event array). For ring buffers, max_entries IS the
// buffer size in bytes.
CALI_RINGBUF(cali_rb_evnt, 1024 * 1024)

// Per-CPU counter for events dropped due to a full ring buffer.
// The Go side polls this map to detect and report lost events.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} cali_rb_drops SEC(".maps");

// Submit helper — drop-in replacement for perf_commit_event().
// Unlike perf_commit_event, does not require a program context pointer.
// On failure (ring buffer full), increments the per-CPU drop counter.
static CALI_BPF_INLINE int ringbuf_submit_event(void *data, __u64 size)
{
	int err = bpf_ringbuf_output(&cali_rb_evnt, data, size, 0);
	if (err != 0) {
		__u32 key = 0;
		__u64 *cnt = bpf_map_lookup_elem(&cali_rb_drops, &key);
		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		}
	}
	return err;
}

#endif /* __CALI_RINGBUF_H__ */
