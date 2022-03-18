// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

/*
 * This file contains "default" implementations of the policy program
 * (selectable at compile time) which tc will load for us when we're
 * attaching a program to a tc hook.  This allows us to control whether
 * the program will allow by default or deny by default in the window
 * before Felix replaces the policy program with its generated version.
 */

#ifndef __CALI_POL_PROG_H__
#define __CALI_POL_PROG_H__

#ifndef CALI_NO_DEFAULT_POLICY_PROG
#ifdef CALI_DEBUG_ALLOW_ALL

/* If we want to just compile the code without defining any policies and to
 * avoid compiling out code paths that are not reachable if traffic is denied,
 * we can compile it with allow all
 */
static CALI_BPF_INLINE enum calico_policy_result execute_policy_norm(struct __sk_buff *skb,
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
#else

static CALI_BPF_INLINE enum calico_policy_result execute_policy_norm(struct __sk_buff *skb,
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

#endif /* CALI_DEBUG_ALLOW_ALL */

SEC("classifier/tc/policy")
int calico_tc_norm_pol_tail(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering normal policy tail call\n");

	struct cali_tc_state *state = state_get();
	if (!state) {
	        CALI_DEBUG("State map lookup failed: DROP\n");
	        goto deny;
	}

	state->pol_rc = execute_policy_norm(skb, state->ip_proto, state->ip_src,
					    state->ip_dst, state->sport, state->dport);

	CALI_JUMP_TO(skb, PROG_INDEX_ALLOWED);
	CALI_DEBUG("Tail call to post-policy program failed: DROP\n");

deny:
	return TC_ACT_SHOT;
}

SEC("classifier/tc/policy_v6")
int calico_tc_v6_norm_pol_tail(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 normal policy tail call\n");
	CALI_JUMP_TO(skb, PROG_INDEX_V6_ALLOWED);
	CALI_DEBUG("Tail call to IPv6 post-policy program failed: DROP\n");
	return TC_ACT_SHOT;
}

#endif /* CALI_DEBUG_NO_PROG */

#endif /*  __CALI_POL_PROG_H__ */
