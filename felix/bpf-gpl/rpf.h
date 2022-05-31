// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_RPF_H__
#define __CALI_RPF_H__

#include "types.h"
#include "skb.h"

static CALI_BPF_INLINE bool wep_rpf_check(struct cali_tc_ctx *ctx, struct cali_rt *r)
{
        CALI_DEBUG("Workload RPF check src=%x skb iface=%d.\n",
                        bpf_ntohl(ctx->state->ip_src), ctx->skb->ifindex);
        if (!r) {
                CALI_INFO("Workload RPF fail: missing route.\n");
                return false;
        }
        if (!cali_rt_flags_local_workload(r->flags)) {
                CALI_INFO("Workload RPF fail: not a local workload.\n");
                return false;
        }
        if (r->if_index != ctx->skb->ifindex) {
                CALI_INFO("Workload RPF fail skb iface (%d) != route iface (%d)\n",
                                ctx->skb->ifindex, r->if_index);
                return false;
        }

        return true;
}

static CALI_BPF_INLINE bool hep_rpf_check(struct cali_tc_ctx *ctx)
{
	bool ret = false;

	if (!(GLOBAL_FLAGS & CALI_GLOBALS_RPF_STRICT_ENABLED)) {
		CALI_DEBUG("Host RPF check disabled\n");
		return true;
	}

	struct bpf_fib_lookup fib_params = {
		.family = 2, /* AF_INET */
		.tot_len = 0,
		.ifindex = ctx->skb->ingress_ifindex,
		.l4_protocol = ctx->state->ip_proto,
		.sport = bpf_htons(ctx->state->dport),
		.dport = bpf_htons(ctx->state->sport),
	};

	/* set the ipv4 here, otherwise the ipv4/6 unions do not get
	 * zeroed properly
	 */
	fib_params.ipv4_src = ctx->state->ip_dst;
	fib_params.ipv4_dst = ctx->state->ip_src;

	int rc = bpf_fib_lookup(ctx->skb, &fib_params, sizeof(fib_params), 0);
	switch(rc) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			ret = ctx->skb->ingress_ifindex == fib_params.ifindex;
	}

	CALI_DEBUG("Host RPF check src=%x skb iface=%d fib rc %d\n",
			bpf_ntohl(ctx->state->ip_src), ctx->skb->ifindex, rc);
	CALI_DEBUG("Host RPF check src=%x skb iface=%d result %d\n",
			bpf_ntohl(ctx->state->ip_src), ctx->skb->ifindex, ret);

	return ret;
}
#endif /* __CALI_FIB_H__ */
