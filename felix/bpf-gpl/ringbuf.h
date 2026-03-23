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

// Shared drop counter and flush timestamp, protected by a spinlock.
// Drops are emitted as EVENT_LOST_EVENTS through the ring buffer itself;
// Go never reads this map directly.
#define CALI_RB_FLUSH_INTERVAL_NS (5ULL * 1000000000ULL) /* 5 seconds */

struct rb_drops_val {
	struct bpf_spin_lock lock;
	__u64 count;
	__u64 last_flush_ts;
};

CALI_MAP_V1(cali_rb_drops, BPF_MAP_TYPE_ARRAY, __u32, struct rb_drops_val, 1, 0)

// ringbuf_flush_drops emits accumulated drop count as a TYPE_LOST_EVENTS
// event through the ring buffer, at most once every CALI_RB_FLUSH_INTERVAL_NS.
static CALI_BPF_INLINE void ringbuf_flush_drops(void)
{
	__u32 key = 0;
	struct rb_drops_val *val = cali_rb_drops_lookup_elem(&key);
	if (!val) {
		return;
	}

	__u64 now = bpf_ktime_get_ns();
	
	bpf_spin_lock(&val->lock);
	if (val->count == 0 || now - val->last_flush_ts < CALI_RB_FLUSH_INTERVAL_NS) {
		bpf_spin_unlock(&val->lock);
		return;
	}

	__u64 dropped = val->count;
	val->count = 0;
	bpf_spin_unlock(&val->lock);

	/* Cannot call bpf_ringbuf_output while holding the lock. */
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
		/* Ring still full — restore the counter so drops are not lost.
		 * Concurrent increments between unlock and here are preserved:
		 * the restore adds back the original amount on top of any new
		 * increments, so the total remains accurate. */
		__sync_fetch_and_add(&val->count, dropped);
		return;
	}

	/* No lock needed: if two CPUs write last_flush_ts concurrently,
	 * both values are near-identical (same bpf_ktime_get_ns epoch),
	 * so the difference is irrelevant for a 5-second interval. */
	val->last_flush_ts = now;
}

// Submit helper — drop-in replacement for perf_commit_event().
// Unlike perf_commit_event, does not require a program context pointer.
// On failure (ring buffer full), increments the shared drop counter.
// On success, flushes accumulated drops if the flush interval has elapsed.
static CALI_BPF_INLINE int ringbuf_submit_event(void *data, __u64 size)
{
	int err = bpf_ringbuf_output(&cali_rb_evnt, data, size, 0);
	if (err != 0) {
		__u32 key = 0;
		struct rb_drops_val *val = cali_rb_drops_lookup_elem(&key);
		if (val) {
			__sync_fetch_and_add(&val->count, 1);
		}
	} else {
		ringbuf_flush_drops();
	}
	return err;
}

#endif /* __CALI_RINGBUF_H__ */
