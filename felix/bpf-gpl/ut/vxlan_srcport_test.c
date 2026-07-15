// Project Calico BPF dataplane programs.
// Copyright (c) 2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "skb.h"

const volatile struct cali_tc_preamble_globals __globals;

/* calico_unittest_entry takes a UDP packet and returns the VXLAN source
 * port that tc.c would assign to a VXLAN encapsulation of a flow with the
 * same sport/dport. It applies the same hash and (optional) port-range
 * mapping as the encap path in tc.c so the test exercises the
 * VXLAN_SRC_PORT_MIN/MAX globals end-to-end.
 */
static CALI_BPF_INLINE int calico_unittest_entry(struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return -1;
	}

	/* Make the macros work: tc.c reads them through globals->data. */
	globals->data = __globals.v4;

	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.ipheader_len = IP_SIZE,
	);
	struct cali_tc_ctx *ctx = &_ctx;
	if (!ctx->counters) {
		return -1;
	}

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		return -1;
	}

	struct udphdr *udp = udp_hdr(ctx);
	__u16 sport = bpf_ntohs(udp->source);
	__u16 dport = bpf_ntohs(udp->dest);

	__u16 vxlan_src_port = sport ^ dport;

	if (VXLAN_SRC_PORT_MIN != 0 && VXLAN_SRC_PORT_MAX != 0) {
		__u16 range = (__u16)(VXLAN_SRC_PORT_MAX - VXLAN_SRC_PORT_MIN) + 1;
		vxlan_src_port = VXLAN_SRC_PORT_MIN + (vxlan_src_port % range);
	}

	return (int)vxlan_src_port;
}
