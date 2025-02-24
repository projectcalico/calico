// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_EVETNS_H__
#define __CALI_EVETNS_H__

#include "bpf.h"
#include "types.h"
#include "perf.h"
#include "jump.h"
#include <linux/bpf_perf_event.h>
#include "events_type.h"
#include "log.h"

static CALI_BPF_INLINE void event_flow_log(struct cali_tc_ctx *ctx)
{
#ifndef IPVER6
	ctx->state->eventhdr.type = EVENT_POLICY_VERDICT,
#else
	ctx->state->eventhdr.type = EVENT_POLICY_VERDICT_V6,
#endif
	ctx->state->eventhdr.len = offsetof(struct cali_tc_state, rule_ids) + sizeof(__u64) * MAX_RULE_IDS;

	/* Due to stack space limitations, the begining of the state is structured as the
	 * event and so we can send the data straight without copying in BPF.
	 */
	int err = perf_commit_event(ctx->skb, ctx->state, ctx->state->eventhdr.len);

	if (err != 0) {
		CALI_DEBUG("event_flow_log: perf_commit_event returns %d\n", err);
	}
}

static CALI_BPF_INLINE bool flow_logs_enabled(struct cali_tc_ctx *ctx)
{
	return (GLOBAL_FLAGS & CALI_GLOBALS_FLOWLOGS_ENABLED);
}

#endif /* __CALI_EVETNS_H__ */
