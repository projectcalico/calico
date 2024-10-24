// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf.h"

#define CALI_LOG(fmt, ...) bpf_log("%s-X: " fmt, ctx->xdp_globals->iface_name, ## __VA_ARGS__)

#include "log.h"
#include "types.h"
#include "counters.h"
#include "skb.h"
#include "routes.h"
#include "reasons.h"
#include "parsing.h"
#include "failsafe.h"
#include "jump.h"
#include "policy.h"
#include "metadata.h"
#include "globals.h"

/* calico_xdp is the main function used in all of the xdp programs */
SEC("xdp")
int calico_xdp_main(struct xdp_md *xdp)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx _ctx = {
		.state = state_get(),
		.counters = counters_get(xdp->ingress_ifindex),
		.xdp_globals = state_get_globals_xdp(),
		.xdp = xdp,
		.fwd = {
			.res = XDP_PASS, // TODO: Adjust based on the design
			.reason = CALI_REASON_UNKNOWN,
		},
		.ipheader_len = IP_SIZE,
	};
	struct cali_tc_ctx *ctx = &_ctx;

	if (!ctx->xdp_globals) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "State map globals lookup failed: DROP");
		return XDP_DROP;
	}

	if (!ctx->state) {
		CALI_DEBUG("State map lookup failed: PASS");
		return XDP_PASS; // TODO: Adjust base on the design
	}
	if (!ctx->counters) {
		CALI_DEBUG("No counters: DROP");
		return XDP_DROP;
	}
	__builtin_memset(ctx->state, 0, sizeof(*ctx->state));
	ctx->scratch = (void *)(ctx->xdp_globals + 1); /* needs to be set to something, not used, there is space */
	ctx->nh = &ctx->scratch->l4;

	counter_inc(ctx, COUNTER_TOTAL_PACKETS);

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx->state->prog_start_time = bpf_ktime_get_ns();
	}

	// Parse packets and drop malformed and unsupported ones
	switch (parse_packet_ip(ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	tc_state_fill_from_iphdr(ctx);

	switch(tc_state_fill_from_nexthdr(ctx, false)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	// Skip XDP policy, and hence fall through to TC processing, if packet hits an
	// entry in the inbound ports failsafe map.  The point here is that flows through
	// configured failsafe ports should be allowed and NOT be accidentally untracked.
	if (is_failsafe_in(ctx->state->ip_proto, ctx->state->dport, ctx->state->ip_src)) {
		CALI_DEBUG("Inbound failsafe port: %d. Skip policy", ctx->state->dport);
		counter_inc(ctx, CALI_REASON_ACCEPTED_BY_FAILSAFE);
		ctx->state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	// Similarly check against the outbound ports failsafe map.  The logic here is
	// that an outbound failsafe port <cidr>:<port> means to allow outbound connection
	// to IPs in <cidr> and destination <port>.  But then the return path - INBOUND,
	// and FROM <cidr>:<port> - will come through this XDP program and we need to make
	// sure that it is (a) not accidentally marked as DoNotTrack, (b) allowed through
	// to the TC program, which will then check that it matches a known outbound
	// conntrack state.
	if (is_failsafe_out(ctx->state->ip_proto, ctx->state->sport, ctx->state->ip_src)) {
		CALI_DEBUG("Outbound failsafe port: %d. Skip policy", ctx->state->sport);
		counter_inc(ctx, CALI_REASON_ACCEPTED_BY_FAILSAFE);
		ctx->state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	// Jump to the policy program
	CALI_DEBUG("About to jump to policy program at %d", ctx->xdp_globals->jumps[PROG_INDEX_POLICY]);
	CALI_JUMP_TO_POLICY(ctx);

allow:
	return XDP_PASS;

deny:
	return XDP_DROP;
}

/* This program contains "default" implementations of the policy program
 * which ip will load for us when we're attaching a program to a xdp hook.
 * This allows us to control the behaviour in the window before Felix replaces
 * the policy program with its generated version.*/
SEC("xdp")
int calico_xdp_norm_pol_tail(struct xdp_md *xdp)
{
	CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "Entering normal policy tail call: PASS");
	return XDP_PASS;
}

SEC("xdp")
int calico_xdp_accepted_entrypoint(struct xdp_md *xdp)
{
	struct cali_tc_ctx _ctx = {
		.xdp = xdp,
		.xdp_globals = state_get_globals_xdp(),
		.counters = counters_get(xdp->ingress_ifindex),
		.fwd = {
			.res = XDP_PASS,
			.reason = CALI_REASON_UNKNOWN,
		},
		.ipheader_len = IP_SIZE,
	};
	struct cali_tc_ctx *ctx = &_ctx;

	if (!ctx->xdp_globals) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "State map xdp globals lookup failed: DROP");
		return XDP_DROP;
	}
	if (!ctx->counters) {
		CALI_DEBUG("No counters: DROP");
		return XDP_DROP;
	}

	ctx->scratch = (void *)(ctx->xdp_globals + 1);

	CALI_DEBUG("Entering calico_xdp_accepted_entrypoint");

	// Share with TC the packet is already accepted and accept it there too.
	if (xdp2tc_set_metadata(ctx, CALI_META_ACCEPTED_BY_XDP)) {
		CALI_DEBUG("Failed to set metadata for TC");
	}
	counter_inc(ctx, CALI_REASON_ACCEPTED_BY_POLICY);

	return XDP_PASS;
}

SEC("xdp")
int calico_xdp_drop(struct xdp_md *xdp)
{
	struct cali_tc_ctx _ctx = {
		.xdp = xdp,
		.state = state_get(),
		.counters = counters_get(xdp->ingress_ifindex),
		.xdp_globals = state_get_globals_xdp(),
		.ipheader_len = IP_SIZE,
	};
	struct cali_tc_ctx *ctx = &_ctx;

	if (!ctx->xdp_globals) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "State map xdp globals lookup failed: DROP");
		return XDP_DROP;
	}
	CALI_DEBUG("Entering calico_xdp_drop");

	if (!ctx->state) {
		CALI_DEBUG("State map lookup failed: no event generated");
		return XDP_DROP;
	}

	if (!ctx->counters) {
		CALI_DEBUG("No counters: DROP");
		return XDP_DROP;
	}

	ctx->scratch = (void *)(ctx->xdp_globals + 1);

	counter_inc(ctx, CALI_REASON_DROPPED_BY_POLICY);

	CALI_DEBUG("proto=%d", ctx->state->ip_proto);
	CALI_DEBUG("src=" IP_FMT " dst=" IP_FMT "", debug_ip(ctx->state->ip_src),
			debug_ip(ctx->state->ip_dst));
	CALI_DEBUG("pre_nat=" IP_FMT ":%d", debug_ip(ctx->state->pre_nat_ip_dst),
			ctx->state->pre_nat_dport);
	CALI_DEBUG("post_nat=" IP_FMT ":%d", debug_ip(ctx->state->post_nat_ip_dst), ctx->state->post_nat_dport);
	CALI_DEBUG("tun_ip=" IP_FMT "", debug_ip(ctx->state->tun_ip));
	CALI_DEBUG("pol_rc=%d", ctx->state->pol_rc);
	CALI_DEBUG("sport=%d", ctx->state->sport);
	CALI_DEBUG("flags=0x%x", ctx->state->flags);
	CALI_DEBUG("ct_rc=%d", ctx->state->ct_result.rc);

	CALI_DEBUG("DENY due to policy");
	return XDP_DROP;
}
