// Project Calico BPF dataplane programs.
// Copyright (c) 2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_QOS_H__
#define __CALI_QOS_H__

#include "bpf.h"
#include "counters.h"
#include "ifstate.h"

static CALI_BPF_INLINE int enforce_packet_rate_qos(struct cali_tc_ctx *ctx)
{
#if !CALI_F_WEP
		return TC_ACT_UNSPEC;
#endif

	// Retrieve ifstate map where TBF state is kept
	struct ifstate_val *ifstate;
	__u32 ifindex = ctx->skb->ifindex;
	if (!(ifstate = cali_iface_lookup_elem(&ifindex))) {
		CALI_DEBUG("packet rate QoS: ifstate not found, accepting packet");
		return TC_ACT_UNSPEC;
	}

#if CALI_F_INGRESS
	if (INGRESS_PACKET_RATE == 0) {
		ifstate->ingress_packet_rate_tokens = -1;
		cali_iface_update_elem(&ifindex, ifstate, BPF_ANY);
		return TC_ACT_UNSPEC;
	}
#else // CALI_F_EGRESS
	if (EGRESS_PACKET_RATE == 0) {
		ifstate->egress_packet_rate_tokens = -1;
		cali_iface_update_elem(&ifindex, ifstate, BPF_ANY);
		return TC_ACT_UNSPEC;
	}
#endif

	CALI_DEBUG("packet rate QoS: configured, enforcing limit");

	__u64 packet_rate;
	__s16 burst_size;
	__u64 last_update;
	__s16 tokens;

#if CALI_F_INGRESS
	packet_rate = INGRESS_PACKET_RATE;
	burst_size = (__s16) INGRESS_PACKET_BURST;
	last_update = ifstate->ingress_packet_rate_last_update;
	tokens = ifstate->ingress_packet_rate_tokens;
#else // CALI_F_EGRESS
	packet_rate = EGRESS_PACKET_RATE;
	burst_size = (__s16) EGRESS_PACKET_BURST;
	last_update = ifstate->egress_packet_rate_last_update;
	tokens = ifstate->egress_packet_rate_tokens;
#endif

	__u64 now = bpf_ktime_get_ns();

	// If not initialized, set initial value of tokens to the burst size
	if (tokens == -1) {
		CALI_DEBUG("packet rate QoS: initializing TBF");
		tokens = burst_size;
		last_update = now;
	}

	// Calculate token increment from elapsed time (now - last_update) and packet_rate
	__s16 tokens_inc = ((now - last_update) * packet_rate) / 1000000000;
	if (tokens_inc > 0) {
		tokens += tokens_inc;

		// Cap tokens to burst_size (TBF bucket size)
		if (tokens > burst_size) {
			tokens = burst_size;
		}

		last_update = now;
	}

	bool accept = false;

	// If there is at least one token available, decrement by one and accept packet
	if (tokens > 0) {
		--tokens;
		accept = true;
	}

	// Update TBF state
#if CALI_F_INGRESS
	ifstate->ingress_packet_rate_last_update = last_update;
	ifstate->ingress_packet_rate_tokens = tokens;

#else // CALI_F_EGRESS
	ifstate->egress_packet_rate_last_update = last_update;
	ifstate->egress_packet_rate_tokens = tokens;
#endif
	cali_iface_update_elem(&ifindex, ifstate, BPF_ANY);

	CALI_DEBUG("packet rate QoS: tokens: %d last_update: %llu", tokens, last_update);

	if (accept) {
		CALI_DEBUG("packet rate QoS: accept");
		return TC_ACT_UNSPEC;
	}

	// If there were not enough tokens, drop packet and increment counter
	counter_inc(ctx, CALI_REASON_DROPPED_BY_QOS);
	CALI_DEBUG("packet rate QoS: drop");
	return TC_ACT_SHOT;
}

#endif /* __CALI_QOS_H__ */
