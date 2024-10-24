// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

/*
 * This file contains "default" implementations of the policy program
 * (selectable at compile time) which tc will load for us when we're
 * attaching a program to a tc hook.  This allows us to control whether
 * the program will allow by default or deny by default in the window
 * before Felix replaces the policy program with its generated version.
 */

#include <stdbool.h>

#include "bpf.h"
#include "log.h"
#include "types.h"
#include "jump.h"
#include "policy.h"

/* If we want to just compile the code without defining any policies and to
 * avoid compiling out code paths that are not reachable if traffic is denied,
 * we can compile it with allow all
 */
static CALI_BPF_INLINE enum calico_policy_result policy_allow(struct __sk_buff *skb,
				__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	RULE_START(0);
	RULE_END(0, allow);

	return CALI_POL_NO_MATCH;
deny:
	return CALI_POL_DENY;
allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALI_BPF_INLINE enum calico_policy_result policy_deny(struct __sk_buff *skb,
				__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	RULE_START(0);
	RULE_END(0, deny);

	return CALI_POL_NO_MATCH;
deny:
	return CALI_POL_DENY;
allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

SEC("tc")
int calico_tc_allow(struct __sk_buff *skb)
{
	struct cali_tc_ctx _ctx = {
		.skb = skb,
		.globals = state_get_globals_tc(),
	};
	struct cali_tc_ctx *ctx = &_ctx;

	if (!ctx->globals) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "State map globals lookup failed: DROP");
		return TC_ACT_SHOT;
	}

	CALI_DEBUG("Entering normal policy program");

#ifndef IPVER6
	struct cali_tc_state *state = state_get();
	if (!state) {
	        CALI_DEBUG("State map lookup failed: DROP");
	        goto deny;
	}

	state->pol_rc = policy_allow(skb, state->ip_proto, state->ip_src,
				     state->ip_dst, state->sport, state->dport);

	CALI_DEBUG("jumping to allowed");
	CALI_JUMP_TO(ctx, PROG_INDEX_ALLOWED);
#else
	CALI_JUMP_TO(ctx, PROG_INDEX_V6_ALLOWED);
#endif
	CALI_DEBUG("Tail call to post-policy program failed: DROP");

deny:
	return TC_ACT_SHOT;
}

SEC("tc")
int calico_tc_deny(struct __sk_buff *skb)
{
	struct cali_tc_ctx _ctx = {
		.skb = skb,
		.globals = state_get_globals_tc(),
	};
	struct cali_tc_ctx *ctx = &_ctx;

	if (!ctx->globals) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "State map globals lookup failed: DROP");
		return TC_ACT_SHOT;
	}

	CALI_DEBUG("Entering normal policy program");

#ifndef IPVER6
	struct cali_tc_state *state = state_get();
	if (!state) {
	        CALI_DEBUG("State map lookup failed: DROP");
	        goto deny;
	}

	state->pol_rc = policy_deny(skb, state->ip_proto, state->ip_src,
				    state->ip_dst, state->sport, state->dport);

	CALI_DEBUG("jumping to allowed");
	CALI_JUMP_TO(ctx, PROG_INDEX_ALLOWED);
#else
	CALI_JUMP_TO(ctx, PROG_INDEX_V6_ALLOWED);
#endif
	CALI_DEBUG("Tail call to post-policy program failed: DROP");

deny:
	return TC_ACT_SHOT;
}
