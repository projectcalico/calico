// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_RINGBUF_H__
#define __CALI_RINGBUF_H__

#include "bpf.h"
#include "events_type.h"

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
// BPFExportBufferSizeMB * NumPossibleCPUs (preserving the same total buffer
// capacity as the old per-CPU perf event array). For ring buffers,
// max_entries IS the buffer size in bytes.
CALI_RINGBUF(cali_rb_evnt, 1024 * 1024)

// Shared drop counter and flush timestamp.
//   key 0: accumulated drop count
//   key 1: last flush timestamp (nanoseconds, from bpf_ktime_get_ns)
// Drops are emitted as EVENT_LOST_EVENTS through the ring buffer itself;
// Go never reads this map directly.
#define CALI_RB_DROPS_KEY_COUNT 0
#define CALI_RB_DROPS_KEY_TS    1
#define CALI_RB_FLUSH_INTERVAL_NS (5ULL * 1000000000ULL) /* 5 seconds */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} cali_rb_drops SEC(".maps");

// ringbuf_flush_drops emits accumulated drop count as a TYPE_LOST_EVENTS
// event through the ring buffer, at most once every CALI_RB_FLUSH_INTERVAL_NS.
static CALI_BPF_INLINE void ringbuf_flush_drops(void)
{
	__u32 cnt_key = CALI_RB_DROPS_KEY_COUNT;
	__u64 *cnt = bpf_map_lookup_elem(&cali_rb_drops, &cnt_key);
	if (!cnt || *cnt == 0) {
		return;
	}

	__u32 ts_key = CALI_RB_DROPS_KEY_TS;
	__u64 *last_ts = bpf_map_lookup_elem(&cali_rb_drops, &ts_key);
	if (!last_ts) {
		return;
	}

	__u64 now = bpf_ktime_get_ns();
	if (now - *last_ts < CALI_RB_FLUSH_INTERVAL_NS) {
		return;
	}

	__u64 dropped = __sync_lock_test_and_set(cnt, 0);
	if (dropped > 0) {
		struct {
			struct event_header hdr;
			__u64 count;
		} evt = {
			.hdr = {
				.type = EVENT_LOST_EVENTS,
				.len  = sizeof(evt),
			},
			.count = dropped,
		};
		if (bpf_ringbuf_output(&cali_rb_evnt, &evt, sizeof(evt), 0) != 0) {
			/* Ring still full — restore counter. */
			__sync_fetch_and_add(cnt, dropped);
			return;
		}
		*last_ts = now;
	}
}

// Submit helper — drop-in replacement for perf_commit_event().
// Unlike perf_commit_event, does not require a program context pointer.
// On failure (ring buffer full), increments the shared drop counter.
// On success, flushes accumulated drops if the flush interval has elapsed.
static CALI_BPF_INLINE int ringbuf_submit_event(void *data, __u64 size)
{
	int err = bpf_ringbuf_output(&cali_rb_evnt, data, size, 0);
	if (err != 0) {
		__u32 key = CALI_RB_DROPS_KEY_COUNT;
		__u64 *cnt = bpf_map_lookup_elem(&cali_rb_drops, &key);
		if (cnt) {
			__sync_fetch_and_add(cnt, 1);
		}
	} else {
		ringbuf_flush_drops();
	}
	return err;
}

#endif /* __CALI_RINGBUF_H__ */
