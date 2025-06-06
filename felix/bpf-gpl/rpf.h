// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_RPF_H__
#define __CALI_RPF_H__

#include "types.h"
#include "skb.h"
#include "routes.h"

#define RPF_RES_FAIL	0
#define RPF_RES_STRICT	1
#define RPF_RES_LOOSE	2

static CALI_BPF_INLINE int wep_rpf_check(struct cali_tc_ctx *ctx, struct cali_rt *r)
{
        CALI_DEBUG("Workload RPF check src=" IP_FMT " skb iface=%d.",
                        debug_ip(ctx->state->ip_src), ctx->skb->ifindex);
        if (!r) {
                CALI_INFO("Workload RPF fail: missing route.");
                return RPF_RES_FAIL;
        }
#ifdef IPVER6
	if (ctx->state->ip_proto == IPPROTO_ICMPV6) {
		return RPF_RES_STRICT;
	}
#endif
        if (!cali_rt_flags_local_workload(r->flags)) {
                CALI_INFO("Workload RPF fail: not a local workload.");
                return RPF_RES_FAIL;
        }
        if (r->if_index != ctx->skb->ifindex) {
                CALI_INFO("Workload RPF fail skb iface (%d) != route iface (%d)",
                                ctx->skb->ifindex, r->if_index);
                return RPF_RES_FAIL;
        }

        return RPF_RES_STRICT;
}

static CALI_BPF_INLINE int hep_rpf_check(struct cali_tc_ctx *ctx)
{
	int ret = RPF_RES_FAIL;
	bool strict;
#ifdef IPVER6
	bool linkLocal = false;
#endif
	if (!(GLOBAL_FLAGS & CALI_GLOBALS_RPF_OPTION_ENABLED)) {
		CALI_DEBUG("Host RPF check disabled");
		return true;
	}

#ifdef IPVER6
	if (ctx->state->ip_proto == IPPROTO_ICMPV6) {
		return true;
	}
	if (ip_link_local(ctx->state->ip_dst) && ip_link_local(ctx->state->ip_src)) {
		linkLocal = true;
	}
#endif

	strict = GLOBAL_FLAGS & CALI_GLOBALS_RPF_OPTION_STRICT;
	struct bpf_fib_lookup fib_params = {
#ifdef IPVER6
		.family = 10, /* AF_INET6 */
#else
		.family = 2, /* AF_INET */
#endif
		.tot_len = 0,
		.ifindex = ctx->skb->ingress_ifindex,
		.l4_protocol = ctx->state->ip_proto,
		.sport = bpf_htons(ctx->state->dport),
		.dport = bpf_htons(ctx->state->sport),
	};

	/* set the ipv4 here, otherwise the ipv4/6 unions do not get
	 * zeroed properly
	 */
#ifdef IPVER6
	ipv6_addr_t_to_be32_4_ip(fib_params.ipv6_src, &ctx->state->ip_dst);
	ipv6_addr_t_to_be32_4_ip(fib_params.ipv6_dst, &ctx->state->ip_src);
#else
	fib_params.ipv4_src = ctx->state->ip_dst;
	fib_params.ipv4_dst = ctx->state->ip_src;
#endif

	int rc = bpf_fib_lookup(ctx->skb, &fib_params, sizeof(fib_params), 0);
	switch(rc) {
		case BPF_FIB_LKUP_RET_SUCCESS:
		case BPF_FIB_LKUP_RET_NO_NEIGH:
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			if (strict) {
				if (ctx->skb->ingress_ifindex == fib_params.ifindex) {
					ret = RPF_RES_STRICT;
				}
#ifdef IPVER6
#ifdef VERIFIER_IS_COOL
				CALI_DEBUG("Host RPF check skb strict if %d", fib_params.ifindex);
#endif
#else
				CALI_DEBUG("Host RPF check src=" IP_FMT " skb strict if %d",
						debug_ip(ctx->state->ip_src), fib_params.ifindex);
#endif
			} else {
				if (ctx->skb->ingress_ifindex == fib_params.ifindex) {
					ret = RPF_RES_STRICT;
				} else if (fib_params.ifindex != CT_INVALID_IFINDEX) {
					ret = RPF_RES_LOOSE;
				}
#ifdef IPVER6
#ifdef VERIFIER_IS_COOL
				CALI_DEBUG("Host RPF check skb loose if %d", fib_params.ifindex);
#endif
#else
				CALI_DEBUG("Host RPF check src=" IP_FMT " skb loose if %d",
						debug_ip(ctx->state->ip_src), fib_params.ifindex);
#endif
			}
			break;
#ifdef IPVER6
		case BPF_FIB_LKUP_RET_NOT_FWDED:
			if (linkLocal) {
				ret = RPF_RES_STRICT;
			}
			break;
#endif

	}

#ifdef IPVER6
#ifdef VERIFIER_IS_COOL
	CALI_DEBUG("Host RPF check skb iface=%d", ctx->skb->ifindex);
#endif
#else
	CALI_DEBUG("Host RPF check src=" IP_FMT " skb iface=%d",
			debug_ip(ctx->state->ip_src), ctx->skb->ifindex);
#endif
	CALI_DEBUG("Host RPF check rc %d result %d", rc, ret);
	return ret;
}
#endif /* __CALI_FIB_H__ */
