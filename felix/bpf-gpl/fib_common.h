// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_FIB_COMMON_H__
#define __CALI_FIB_COMMON_H__

#include "types.h"
#include "skb.h"
#include "ifstate.h"

#if CALI_FIB_ENABLED
#define fwd_fib(fwd)			((fwd)->fib)
#define fwd_fib_set(fwd, v)		((fwd)->fib = v)
#define fwd_fib_set_flags(fwd, flags)	((fwd)->fib_flags = flags)
#else
#define fwd_fib(fwd)	false
#define fwd_fib_set(fwd, v)
#define fwd_fib_set_flags(fwd, flags)
#endif

static CALI_BPF_INLINE bool fib_approve(struct cali_tc_ctx *ctx, __u32 ifindex)
{
#ifdef UNITTEST
	/* Let's assume that unittest is setup so that WEP's are ready - for UT simplicity */
	return true;
#else
	/* If we are turning packets around on lo to a remote pod, approve the
	 * fib as it does not concern a possibly not ready local WEP.
	 */
	if (CALI_F_TO_HEP && ctx->state->flags & CALI_ST_CT_NP_REMOTE) {
		return true;
	}

	struct cali_tc_state *state = ctx->state;

	/* To avoid forwarding packets to workloads that are not yet ready, i.e
	 * their tc programs are not attached yet, send unconfirmed packets via
	 * iptables that will filter out packets to non-ready workloads.
	 */
	if (!ct_result_is_confirmed(state->ct_result.rc)) {
		struct ifstate_val *val;

		if (!(val = (struct ifstate_val *)cali_iface_lookup_elem(&ifindex))) {
			CALI_DEBUG("FIB not approved - connection to unknown ep %d not confirmed.", ifindex);
			return false;
		}
		if (iface_is_workload(val->flags) && !iface_is_ready(val->flags)) {
			ctx->fwd.mark |= CALI_SKB_MARK_SKIP_FIB;
			CALI_DEBUG("FIB not approved - connection to unready ep %s (ifindex %d) not confirmed.",
					val->name, ifindex);
			CALI_DEBUG("FIB not approved - connection to unready ep %s (flags 0x%x) not confirmed.",
					val->name, val->flags);
			return false;
		}
	}

	return true;
#endif
}


#endif /* __CALI_FIB_COMMON_H__ */
