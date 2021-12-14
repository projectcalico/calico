// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


// NOTE: THIS FILE IS NOT YET IN ACTIVE USE.

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
#include "icmp.h"
#include "fib.h"
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

	// Allow a packet if it hits an entry in the failsafe map
	if (is_failsafe_in(ctx.state->ip_proto, ctx.state->dport, ctx.state->ip_src)) {
		CALI_DEBUG("Inbound failsafe port: %d. Skip policy\n", ctx.state->dport);
		ctx.state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	// Jump to the policy program
	CALI_DEBUG("About to jump to policy program.\n");
	bpf_tail_call(xdp, &cali_jump, PROG_INDEX_POLICY);

allow:
	return XDP_PASS;

deny:
	return XDP_DROP;
}

__attribute__((section("1/1")))
int calico_xdp_accepted_entrypoint(struct xdp_md *xdp)
{
	CALI_DEBUG("Entring calico_xdp_accepted_entrypoint\n");
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */

	// Share with TC the packet is already accepted and accept it there too.
	if (xdp2tc_set_metadata(xdp, CALI_META_ACCEPTED_BY_XDP)) {
		CALI_DEBUG("Failed to set metadata for TC\n");
	}

	return XDP_PASS;
}

#ifndef CALI_ENTRYPOINT_NAME_XDP
#define CALI_ENTRYPOINT_NAME_XDP calico_entrypoint_xdp
#endif

// Entrypoint with definable name.  It's useful to redefine the name for each entrypoint
// because the name is exposed by bpftool et al.
__attribute__((section(XSTR(CALI_ENTRYPOINT_NAME_XDP))))
int xdp_calico_entry(struct xdp_md *xdp)
{
	return calico_xdp(xdp);
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
