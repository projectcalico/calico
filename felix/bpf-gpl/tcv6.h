// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALICO_TCV6_H__
#define __CALICO_TCV6_H__

SEC("classifier/tc/prologue_v6")
int calico_tc_v6(struct __sk_buff *skb)
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

	switch (parse_packet_ipv6(&ctx, 1)) {
	case PARSING_OK_V6:
		break;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow_no_fib;
	case PARSING_ERROR:
	default:
		goto deny;
	}

	ipv6_log_addr(ipv6_hdr(&ctx));
	CALI_DEBUG("l4 protocol: %d", ctx.state->ip_proto);

	if (CALI_F_WEP) {
		CALI_DEBUG("IPv6 from workload: drop\n");
		goto deny;
	}
	CALI_DEBUG("IPv6 on host interface: allow\n");
	CALI_DEBUG("About to jump to normal policy program\n");
	CALI_JUMP_TO(skb, PROG_INDEX_V6_POLICY);
	CALI_DEBUG("Tail call to normal policy program failed: DROP\n");

allow_no_fib:
	return TC_ACT_UNSPEC;

deny:
	return TC_ACT_SHOT;
}

SEC("classifier/tc/accept_v6")
int calico_tc_v6_skb_accepted_entrypoint(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 accepted program\n");
	// TODO: Implement the logic for accepted packets by the policy program
	// We should not reach here since no tail call happens to this program
	skb->mark = CALI_SKB_MARK_SEEN;
	return TC_ACT_UNSPEC;
}

SEC("classifier/tc/icmp_v6")
int calico_tc_v6_skb_send_icmp_replies(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 icmp program\n");
	// TODO: Implement the logic for accepted icmp packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

SEC("classifier/tc/drop_v6")
int calico_tc_v6_skb_drop(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 drop program\n");
	// TODO: Implement the logic for dropped packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

#endif /* __CALICO_TCV6_H__ */
