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
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
		.iphdr_len = IPv6_SIZE,
	};
	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}
	__builtin_memset(ctx.state, 0, sizeof(*ctx.state));

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx.state->prog_start_time = bpf_ktime_get_ns();
	}

	switch (parse_packet_ipv6(&ctx)) {
	case PARSING_OK_V6:
		break;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow_no_fib;
	case PARSING_ERROR:
	default:
		goto deny;
	}

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		ctx.fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	//CALI_DEBUG("IPv6 s=%ld d=%ld\n", ipv6hdr(ctx)->saddr.in6_u.u6_addr32[0], ipv6hdr(ctx)->daddr.in6_u.u6_addr32[0]);
	CALI_DEBUG("IPhdr_len: %d", ctx.iphdr_len);
	//CALI_DEBUG("Protocol: %d", ipv6hdr(&ctx)->nexthdr);
	CALI_DEBUG("SKB: %x", ctx.data_start);
	CALI_DEBUG("ip: %x", ctx.ip_header);
	CALI_DEBUG("nh: %x", ctx.nh);

	switch (ctx.state->ip_proto) {
	case IPPROTO_UDP:
		CALI_DEBUG("UDP\n");
		break;
	case IPPROTO_TCP:
		CALI_DEBUG("TCP\n");
		break;
	case IPPROTO_ICMPV6:
		CALI_DEBUG("ICMPv6\n");
		break;
	default:
		CALI_DEBUG("Failed to parse IPv6 packet\n");
		goto deny;
	}

	if (CALI_F_WEP) {
		CALI_DEBUG("IPv6 from workload: drop\n");
		goto deny;
	}

	CALI_DEBUG("IPv6 on host interface: allow\n");
	return TC_ACT_UNSPEC;


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
	return TC_ACT_SHOT;
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
