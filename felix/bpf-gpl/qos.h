// Project Calico BPF dataplane programs.
// Copyright (c) 2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_QOS_H__
#define __CALI_QOS_H__

#include "bpf.h"
#include "skb.h"
#include "counters.h"
#include "ifstate.h"

struct calico_qos_key {
	__u32 ifindex;
	__u32 ingress; // 0=egress; 1=ingress;
};

struct calico_qos_val {
	struct bpf_spin_lock lock;
	// config
	__s16 packet_rate;
	__s16 packet_burst;
	// state
	__s16 packet_rate_tokens;
	__s16 padding[3]; // alignment
	__u64 packet_rate_last_update;
};

// 2*IFACE_STATE_MAP_SIZE because it will potentially have 2 entries for each interface (ingress/egress)
CALI_MAP(cali_qos,,
		BPF_MAP_TYPE_HASH,
		struct calico_qos_key, struct calico_qos_val,
		2*IFACE_STATE_MAP_SIZE, BPF_F_NO_PREALLOC)

static CALI_BPF_INLINE int qos_enforce_packet_rate(struct cali_tc_ctx *ctx)
{
#if CALI_F_INGRESS
	if (!INGRESS_PACKET_RATE_CONFIGURED) {
		return TC_ACT_UNSPEC;
	}
#else // CALI_F_EGRESS
	if (!EGRESS_PACKET_RATE_CONFIGURED) {
		return TC_ACT_UNSPEC;
	}
#endif

	// Retrieve qos map where TBF state is kept
	struct calico_qos_val *qos;
	struct calico_qos_key key = {
		.ifindex = ctx->skb->ifindex,
#if CALI_F_INGRESS
		.ingress = 1,
#else // CALI_F_EGRESS
		.ingress = 0,
#endif
	};
	if (!(qos = cali_qos_lookup_elem(&key))) {
		CALI_DEBUG("packet rate QoS: qos map entry not found, accepting packet");
		return TC_ACT_UNSPEC;
	}

	CALI_DEBUG("packet rate QoS: configured, enforcing limit");

	__u64 now = bpf_ktime_get_ns();

	CALI_DEBUG("packet rate QoS: begin; tokens: %d last_update: %llu", qos->packet_rate_tokens, qos->packet_rate_last_update);

	bpf_spin_lock(&qos->lock);

	// If not initialized, set initial value of tokens to the burst size
	if (qos->packet_rate_tokens == -1) {
		qos->packet_rate_tokens = qos->packet_burst;
		qos->packet_rate_last_update = now;
	}

	// Calculate token increment from elapsed time (now - last_update) and packet_rate
	__s16 tokens_inc = ((now - qos->packet_rate_last_update) * qos->packet_rate) / 1000000000;
	if (tokens_inc > 0) {
		qos->packet_rate_tokens += tokens_inc;

		// Cap tokens to burst_size (TBF bucket size)
		if (qos->packet_rate_tokens > qos->packet_burst) {
			qos->packet_rate_tokens = qos->packet_burst;
		}

		qos->packet_rate_last_update = now;
	}

	bool accept = false;

	// If there is at least one token available, decrement by one and accept packet
	if (qos->packet_rate_tokens > 0) {
		--(qos->packet_rate_tokens);
		accept = true;
	}

	bpf_spin_unlock(&qos->lock);

	CALI_DEBUG("packet rate QoS: end; tokens: %d last_update: %llu", qos->packet_rate_tokens, qos->packet_rate_last_update);

	if (accept) {
		CALI_DEBUG("packet rate QoS: accept");
		return TC_ACT_UNSPEC;
	}

	// If there were not enough tokens, drop packet
	CALI_DEBUG("packet rate QoS: drop");
	return TC_ACT_SHOT;
}

static CALI_BPF_INLINE bool qos_set_dscp(struct cali_tc_ctx *ctx)
{
	// TODO (mazdak): set DSCP only if traffic is leaving cluster
	__s8 dscp = EGRESS_DSCP;
	CALI_DEBUG("setting dscp to %d", dscp);

#ifdef IPVER6
	// In IPv6, traffic class (8bits) equals to DSCP (6bits) + ECN (2bits). The 4 most significant bits of
	// traffic class are stored in IPv6 priority field (4 bits), and the 4 least significant bits of it
	// are stored in the 4 most significant bits of IPv6 flow_lbl[0] field. We must not change ECN bits here.
	ip_hdr(ctx)->priority = (__u8) (dscp >> 2);
	ip_hdr(ctx)->flow_lbl[0] = (__u8) (ip_hdr(ctx)->flow_lbl[0] & 0x3f) | (dscp << 6);
#else
	// In IPv4, DSCP (6bits) is located at the most significant bits of IPv4 TOS field.
	// The 2 least significant bits are assigned to ECN and must not be touched.
	ip_hdr(ctx)->tos = (__u8) ((ip_hdr(ctx)->tos & 0x03) | (dscp << 2));

	ip_hdr(ctx)->check = 0;
	__wsum ip_csum = bpf_csum_diff(0, 0, (__u32 *)ip_hdr(ctx), sizeof(struct iphdr), 0);
	int ret = bpf_l3_csum_replace(ctx->skb, skb_iphdr_offset(ctx) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG("IP DSCP: set L3 csum failed");
		deny_reason(ctx, CALI_REASON_CSUM_FAIL);
		return false;
	}

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		CALI_DEBUG("Too short");
		deny_reason(ctx, CALI_REASON_SHORT);
		return false;
	}
#endif /* IPVER6 */
	return true;
}

#endif /* __CALI_QOS_H__ */
