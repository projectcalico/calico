/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef _TOOLS_LINUX_RING_BUFFER_H_
#define _TOOLS_LINUX_RING_BUFFER_H_

#include <linux/compiler.h>

static inline __u64 ring_buffer_read_head(struct perf_event_mmap_page *base)
{
	return smp_load_acquire(&base->data_head);
}

static inline void ring_buffer_write_tail(struct perf_event_mmap_page *base,
					  __u64 tail)
{
	smp_store_release(&base->data_tail, tail);
}

#endif /* _TOOLS_LINUX_RING_BUFFER_H_ */
