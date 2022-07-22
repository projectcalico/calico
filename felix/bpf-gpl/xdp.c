// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "log.h"
#include "skb.h"
#include "routes.h"
#include "reasons.h"
#include "parsing.h"
#include "failsafe.h"
#include "jump.h"
#include "metadata.h"

/* calico_xdp is the main function used in all of the xdp programs */
static CALI_BPF_INLINE int calico_xdp(struct xdp_md *xdp)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.counters = counters_get(),
		.xdp = xdp,
		.fwd = {
			.res = XDP_PASS, // TODO: Adjust based on the design
			.reason = CALI_REASON_UNKNOWN,
		},
	};

	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: PASS\n");
		return XDP_PASS; // TODO: Adjust base on the design
	}
	__builtin_memset(ctx.state, 0, sizeof(*ctx.state));

	if (!ctx.counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		// We don't want to drop packets just because counters initialization fails, but
		// failing here normally should not happen.
		return XDP_DROP;
	}
	COUNTER_INC(&ctx, COUNTER_TOTAL_PACKETS);

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx.state->prog_start_time = bpf_ktime_get_ns();
	}

	// Parse packets and drop malformed and unsupported ones
	switch (parse_packet_ip(&ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	tc_state_fill_from_iphdr(&ctx);

	switch(tc_state_fill_from_nexthdr(&ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	// Skip XDP policy, and hence fall through to TC processing, if packet hits an
	// entry in the inbound ports failsafe map.  The point here is that flows through
	// configured failsafe ports should be allowed and NOT be accidentally untracked.
	if (is_failsafe_in(ctx.state->ip_proto, ctx.state->dport, ctx.state->ip_src)) {
		CALI_DEBUG("Inbound failsafe port: %d. Skip policy\n", ctx.state->dport);
		COUNTER_INC(&ctx, CALI_REASON_ACCEPTED_BY_FAILSAFE);
		ctx.state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	// Similarly check against the outbound ports failsafe map.  The logic here is
	// that an outbound failsafe port <cidr>:<port> means to allow outbound connection
	// to IPs in <cidr> and destination <port>.  But then the return path - INBOUND,
	// and FROM <cidr>:<port> - will come through this XDP program and we need to make
	// sure that it is (a) not accidentally marked as DoNotTrack, (b) allowed through
	// to the TC program, which will then check that it matches a known outbound
	// conntrack state.
	if (is_failsafe_out(ctx.state->ip_proto, ctx.state->sport, ctx.state->ip_src)) {
		CALI_DEBUG("Outbound failsafe port: %d. Skip policy\n", ctx.state->sport);
		COUNTER_INC(&ctx, CALI_REASON_ACCEPTED_BY_FAILSAFE);
		ctx.state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	// Jump to the policy program
	CALI_DEBUG("About to jump to policy program.\n");
	CALI_JUMP_TO(xdp, PROG_INDEX_POLICY);

allow:
	return XDP_PASS;

deny:
	return XDP_DROP;
}

static CALI_BPF_INLINE int calico_xdp_accept(struct xdp_md *xdp)
{
	struct cali_tc_ctx ctx = {
		.counters = counters_get(),
	};

	if (!ctx.counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return XDP_DROP;
	}
	// Share with TC the packet is already accepted and accept it there too.
	if (xdp2tc_set_metadata(xdp, CALI_META_ACCEPTED_BY_XDP)) {
		CALI_DEBUG("Failed to set metadata for TC\n");
	}
	COUNTER_INC(&ctx, CALI_REASON_ACCEPTED_BY_POLICY);
	return XDP_PASS;
}

/* This program contains "default" implementations of the policy program
 * which libbpf will load for us when we're attaching a program to a xdp hook.
 * This allows us to control the behaviour in the window before Felix replaces
 * the policy program with its generated version.*/
SEC("xdp/policy")
int calico_xdp_norm_pol_tail(struct xdp_md *xdp)
{
	CALI_DEBUG("Entering normal policy tail call: PASS\n");
	return calico_xdp_accept(xdp);
}

SEC("xdp/accept")
int calico_xdp_accepted_entrypoint(struct xdp_md *xdp)
{
	CALI_DEBUG("Entering calico_xdp_accepted_entrypoint\n");
	return calico_xdp_accept(xdp);
}

SEC("xdp/drop")
int calico_xdp_drop(struct xdp_md *xdp)
{
	CALI_DEBUG("Entering calico_xdp_drop\n");
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.counters = counters_get(),
	};

	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: no event generated\n");
		return XDP_DROP;
	}

	if (!ctx.counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return XDP_DROP;
	}
	COUNTER_INC(&ctx, CALI_REASON_DROPPED_BY_POLICY);

	CALI_DEBUG("proto=%d\n", ctx.state->ip_proto);
	CALI_DEBUG("src=%x dst=%x\n", bpf_ntohl(ctx.state->ip_src),
			bpf_ntohl(ctx.state->ip_dst));
	CALI_DEBUG("pre_nat=%x:%d\n", bpf_ntohl(ctx.state->pre_nat_ip_dst),
			ctx.state->pre_nat_dport);
	CALI_DEBUG("post_nat=%x:%d\n", bpf_ntohl(ctx.state->post_nat_ip_dst), ctx.state->post_nat_dport);
	CALI_DEBUG("tun_ip=%x\n", ctx.state->tun_ip);
	CALI_DEBUG("pol_rc=%d\n", ctx.state->pol_rc);
	CALI_DEBUG("sport=%d\n", ctx.state->sport);
	CALI_DEBUG("flags=0x%x\n", ctx.state->flags);
	CALI_DEBUG("ct_rc=%d\n", ctx.state->ct_result.rc);

	return XDP_DROP;
}

#ifndef CALI_ENTRYPOINT_NAME_XDP
#define CALI_ENTRYPOINT_NAME_XDP calico_entrypoint
#endif

// Entrypoint with definable name.  It's useful to redefine the name for each entrypoint
// because the name is exposed by bpftool et al.
SEC("xdp/"XSTR(CALI_ENTRYPOINT_NAME_XDP))
int xdp_calico_entry(struct xdp_md *xdp)
{
	return calico_xdp(xdp);
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
