// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_EVENTS_TYPE_H__
#define __CALI_EVENTS_TYPE_H__

#define EVENT_LOST_EVENTS          0

#define EVENT_PROTO_STATS       1
#define EVENT_DNS               2
#define EVENT_POLICY_VERDICT    3
#define EVENT_TCP_STATS         4
#define EVENT_PROCESS_PATH      5
#define EVENT_DNS_L3            6

#define EVENT_POLICY_VERDICT_V6    7

/* We need the header to be 64bit of size so that any 64bit fields in the
 * message structures that embed this header are also aligned.
 */
struct event_header {
	__u32 type;
	__u32 len;
};

struct event_timestamp_header {
	struct event_header h;
	__u64 timestamp_ns;
};

#endif /* __CALI_EVENTS_TYPE_H__ */
