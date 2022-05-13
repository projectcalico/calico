// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_FIB_H__
#define __CALI_FIB_H__

#include "types.h"
#include "skb.h"

#if CALI_FIB_ENABLED
#define fwd_fib(fwd)			((fwd)->fib)
#define fwd_fib_set(fwd, v)		((fwd)->fib = v)
#define fwd_fib_set_flags(fwd, flags)	((fwd)->fib_flags = flags)
#else
#define fwd_fib(fwd)	false
#define fwd_fib_set(fwd, v)
#define fwd_fib_set_flags(fwd, flags)
#endif

static CALI_BPF_INLINE int forward_or_drop(struct cali_tc_ctx *ctx)
{
	int rc = ctx->fwd.res;
	enum calico_reason reason = ctx->fwd.reason;
	struct cali_tc_state *state = ctx->state;

	if (rc == TC_ACT_SHOT) {
		goto deny;
	}

	if (rc == CALI_RES_REDIR_BACK) {
		int redir_flags = 0;
		if  (CALI_F_FROM_HOST) {
			redir_flags = BPF_F_INGRESS;
		}

		/* Revalidate the access to the packet */
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}

		/* Swap the MACs as we are turning it back */
		struct ethhdr *eth_hdr = ctx->data_start;
		unsigned char mac[ETH_ALEN];
		__builtin_memcpy(mac, &eth_hdr->h_dest, ETH_ALEN);
		__builtin_memcpy(&eth_hdr->h_dest, &eth_hdr->h_source, ETH_ALEN);
		__builtin_memcpy(&eth_hdr->h_source, mac, ETH_ALEN);

		rc = bpf_redirect(ctx->skb->ifindex, redir_flags);
		if (rc == TC_ACT_REDIRECT) {
			CALI_DEBUG("Redirect to the same interface (%d) succeeded.\n", ctx->skb->ifindex);
			goto skip_fib;
		}

		CALI_DEBUG("Redirect to the same interface (%d) failed.\n", ctx->skb->ifindex);
		goto deny;
	} else if (rc == CALI_RES_REDIR_IFINDEX) {
		struct arp_value *arpv;
		__u32 iface = state->ct_result.ifindex_fwd;

		struct arp_key arpk = {
			.ip = state->ip_dst,
			.ifindex = iface,
		};

		arpv = cali_v4_arp_lookup_elem(&arpk);
		if (!arpv) {
			CALI_DEBUG("ARP lookup failed for %x dev %d\n",
					bpf_ntohl(state->ip_dst), iface);
			goto skip_redir_ifindex;
		}

		/* Revalidate the access to the packet */
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}

		/* Patch in the MAC addresses that should be set on the next hop. */
		struct ethhdr *eth_hdr = ctx->data_start;
		__builtin_memcpy(&eth_hdr->h_dest, arpv->mac_dst, ETH_ALEN);
		__builtin_memcpy(&eth_hdr->h_source, arpv->mac_src, ETH_ALEN);

		rc = bpf_redirect(iface, 0);
		if (rc == TC_ACT_REDIRECT) {
			CALI_DEBUG("Redirect directly to interface (%d) succeeded.\n", iface);
			goto skip_fib;
		}

skip_redir_ifindex:
		CALI_DEBUG("Redirect directly to interface (%d) failed.\n", iface);
		/* fall through to FIB if enabled or the IP stack, don't give up yet. */
		rc = TC_ACT_UNSPEC;
	}

#if CALI_FIB_ENABLED
	// Try a short-circuit FIB lookup.
	if (fwd_fib(&ctx->fwd)) {
		/* XXX we might include the tot_len in the fwd, set it once when
		 * we get the ip_header the first time and only adjust the value
		 * when we modify the packet - to avoid geting the header here
		 * again - it is simpler though.
		 */

		/* Revalidate the access to the packet */
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}

		/* Since we are going to short circuit the IP stack on
		 * forward, check if TTL is still alive. If not, let the
		 * IP stack handle it. It was approved by policy, so it
		 * is safe.
		 */
		if ip_ttl_exceeded(ctx->ip_header) {
			rc = TC_ACT_UNSPEC;
			goto cancel_fib;
		}

		struct bpf_fib_lookup fib_params = {
			.family = 2, /* AF_INET */
			.tot_len = 0,
			.ifindex = ctx->skb->ingress_ifindex,
			.l4_protocol = state->ip_proto,
			.sport = bpf_htons(state->sport),
			.dport = bpf_htons(state->dport),
		};

		/* set the ipv4 here, otherwise the ipv4/6 unions do not get
		 * zeroed properly
		 */
		fib_params.ipv4_src = state->ip_src;
		fib_params.ipv4_dst = state->ip_dst;

		CALI_DEBUG("FIB family=%d\n", fib_params.family);
		CALI_DEBUG("FIB tot_len=%d\n", fib_params.tot_len);
		CALI_DEBUG("FIB ifindex=%d\n", fib_params.ifindex);
		CALI_DEBUG("FIB l4_protocol=%d\n", fib_params.l4_protocol);
		CALI_DEBUG("FIB sport=%d\n", bpf_ntohs(fib_params.sport));
		CALI_DEBUG("FIB dport=%d\n", bpf_ntohs(fib_params.dport));
		CALI_DEBUG("FIB ipv4_src=%x\n", bpf_ntohl(fib_params.ipv4_src));
		CALI_DEBUG("FIB ipv4_dst=%x\n", bpf_ntohl(fib_params.ipv4_dst));

		CALI_DEBUG("Traffic is towards the host namespace, doing Linux FIB lookup\n");
		rc = bpf_fib_lookup(ctx->skb, &fib_params, sizeof(fib_params), ctx->fwd.fib_flags);
		switch (rc) {
		case 0:
			CALI_DEBUG("FIB lookup succeeded - with neigh\n");

			// Update the MACs.
			struct ethhdr *eth_hdr = ctx->data_start;
			__builtin_memcpy(&eth_hdr->h_source, fib_params.smac, sizeof(eth_hdr->h_source));
			__builtin_memcpy(&eth_hdr->h_dest, fib_params.dmac, sizeof(eth_hdr->h_dest));

			// Redirect the packet.
			CALI_DEBUG("Got Linux FIB hit, redirecting to iface %d.\n", fib_params.ifindex);
			rc = bpf_redirect(fib_params.ifindex, 0);

			break;

#ifdef BPF_CORE_SUPPORTED
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_redirect_neigh)) {
				CALI_DEBUG("FIB lookup succeeded - not neigh - gw %x\n", bpf_ntohl(fib_params.ipv4_dst));
				struct bpf_redir_neigh nh_params = {};

				nh_params.nh_family = fib_params.family;
				nh_params.ipv4_nh = fib_params.ipv4_dst;

				CALI_DEBUG("Got Linux FIB hit, redirecting to iface %d.\n", fib_params.ifindex);
				rc = bpf_redirect_neigh(fib_params.ifindex, &nh_params, sizeof(nh_params), 0);
				break;
			} else {
				/* fallthrough to handling error */
			}
#endif

		default:
			if (rc < 0) {
				CALI_DEBUG("FIB lookup failed (bad input): %d.\n", rc);
				rc = TC_ACT_UNSPEC;
			} else {
				CALI_DEBUG("FIB lookup failed (FIB problem): %d.\n", rc);
				rc = TC_ACT_UNSPEC;
			}

			break;
		}

		/* now we know we will bypass IP stack and ip->ttl > 1, decrement it! */
		if (rc == TC_ACT_REDIRECT) {
			ip_dec_ttl(ctx->ip_header);
		}
	}

cancel_fib:
#endif /* CALI_FIB_ENABLED */

skip_fib:

	if (CALI_F_TO_HOST) {
		/* Packets received from the tunnel should be forwarded */
               if (CALI_F_FROM_HEP && state->tun_ip != 0 && ctx->fwd.mark != CALI_SKB_MARK_BYPASS_FWD) {
                       ctx->fwd.mark = CALI_SKB_MARK_BYPASS;
               }

		/* Packet is towards host namespace, mark it so that downstream
		 * programs know that they're not the first to see the packet.
		 */
		ctx->fwd.mark |=  CALI_SKB_MARK_SEEN;
		if (ctx->state->ct_result.flags & CALI_CT_FLAG_EXT_LOCAL) {
			CALI_DEBUG("To host marked with FLAG_EXT_LOCAL\n");
			ctx->fwd.mark |= EXT_TO_SVC_MARK;
		}
		CALI_DEBUG("Traffic is towards host namespace, marking with %x.\n", ctx->fwd.mark);
		/* FIXME: this ignores the mask that we should be using.
		 * However, if we mask off the bits, then clang spots that it
		 * can do a 16-bit store instead of a 32-bit load/modify/store,
		 * which trips up the validator.
		 */
		ctx->skb->mark = ctx->fwd.mark; /* make sure that each pkt has SEEN mark */
	}

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		__u64 prog_end_time = bpf_ktime_get_ns();
		CALI_INFO("Final result=ALLOW (%d). Program execution time: %lluns\n",
				reason, prog_end_time-state->prog_start_time);
	}

	return rc;

deny:
	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		__u64 prog_end_time = bpf_ktime_get_ns();
		CALI_INFO("Final result=DENY (%x). Program execution time: %lluns\n",
				reason, prog_end_time-state->prog_start_time);
	}

	return TC_ACT_SHOT;
}

#endif /* __CALI_FIB_H__ */
