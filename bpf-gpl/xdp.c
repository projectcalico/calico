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

SEC("prog")
int calico_xdp(struct xdp_md *xdp_ctx) {
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.xdp = xdp_ctx,
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
	case -1:
		ctx.fwd.res = XDP_DROP;
		goto deny;
	case -2:
		ctx.fwd.res = XDP_PASS;
		goto allow;
	}

	tc_state_fill_from_iphdr(ctx.state, ctx.ip_header);

	switch(parse_packet_nextheader(&ctx)) {
	case -1:
		ctx.fwd.res = XDP_DROP;
		goto deny;
	case -2:
		ctx.fwd.res = XDP_PASS;
		goto allow;
	}

	if (is_failsafe_in(ctx.state->ip_proto, ctx.state->dport, ctx.state->ip_src)) {
		CALI_DEBUG("Inbound failsafe port: %d. Skip policy\n", ctx.state->post_nat_dport);
		ctx.state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	return XDP_DROP;

allow:
	return XDP_PASS;

deny:
	return XDP_DROP;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
