// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ipv6.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "log.h"
#include "skb.h"
#include "routes.h"
#include "parsing.h"
#include "ipv6.h"
#include "jump.h"
#include "policy_program.h"

const volatile struct cali_tc_globals __globals;


SEC("classifier/tc/prologue")
int calico_tc(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 prologue program\n");
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.counters = counters_get(),
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
		.ipheader_len = IPv6_SIZE,
	};

	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	if (!ctx.counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		// We don't want to drop packets just because counters initialization fails, but
		// failing here normally should not happen.
		return TC_ACT_SHOT;
	}
	// TODO: Add IPv6 counters

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx.state->prog_start_time = bpf_ktime_get_ns();
	}

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		DENY_REASON(&ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	tc_state_fill_from_ipv6hdr(&ctx);

	/* Parse out the source/dest ports (or type/code for ICMP). */
	switch (tc_state_fill_from_nexthdr(&ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	CALI_LOG_IPV6(ipv6_hdr(&ctx));
	CALI_DEBUG("IP src=%x\n", ctx.state->ip_src);
	CALI_DEBUG("IP src1=%x\n", ctx.state->ip_src1);
	CALI_DEBUG("IP src2=%x\n", ctx.state->ip_src2);
	CALI_DEBUG("IP src3=%x\n", ctx.state->ip_src3);
	CALI_DEBUG("proto=%d\n", ctx.state->ip_proto);
	CALI_DEBUG("sport=%d\n", ctx.state->sport);
	CALI_DEBUG("dport=%d\n", ctx.state->dport);

	if (CALI_F_WEP) {
		CALI_DEBUG("IPv6 from workload: drop\n");
		goto deny;
	}
	CALI_DEBUG("IPv6 on host interface: allow\n");
	CALI_DEBUG("About to jump to normal policy program\n");
	CALI_JUMP_TO(skb, PROG_INDEX_V6_POLICY);
	if (CALI_F_HEP) {
		CALI_DEBUG("HEP with no policy, allow.\n");
		goto allow;
	}
	CALI_DEBUG("Tail call to normal policy program failed: DROP\n");
	
deny:
	skb->mark = CALI_SKB_MARK_SEEN;
	return TC_ACT_SHOT;

allow:
	skb->mark = CALI_SKB_MARK_SEEN;
	return TC_ACT_UNSPEC;
}

SEC("classifier/tc/accept")
int calico_tc_skb_accepted_entrypoint(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 accepted program\n");
	// TODO: Implement the logic for accepted packets by the policy program
	// We should not reach here since no tail call happens to this program
	skb->mark = CALI_SKB_MARK_SEEN;
	return TC_ACT_UNSPEC;
}

SEC("classifier/tc/icmp")
int calico_tc_skb_send_icmp_replies(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 icmp program\n");
	// TODO: Implement the logic for accepted icmp packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

SEC("classifier/tc/drop")
int calico_tc_skb_drop(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 drop program\n");
	// TODO: Implement the logic for dropped packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

