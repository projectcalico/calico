// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_FIB_H__
#define __CALI_FIB_H__

#include "types.h"
#include "skb.h"
#include "ifstate.h"
#include "profiling.h"

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
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short");
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
			CALI_DEBUG("Redirect to the same interface (%d) succeeded.", ctx->skb->ifindex);
			goto skip_fib;
		}

		CALI_DEBUG("Redirect to the same interface (%d) failed.", ctx->skb->ifindex);
		goto deny;
	} else if (rc == CALI_RES_REDIR_IFINDEX) {
		__u32 iface = state->ct_result.ifindex_fwd;

		struct arp_value *arpv;

		struct arp_key arpk = {
			.ip = iface != NATIN_IFACE ? state->ip_dst : VOID_IP,
			.ifindex = iface,
		};

		arpv = cali_arp_lookup_elem(&arpk);
		if (!arpv) {
			CALI_DEBUG("ARP lookup failed for " IP_FMT " dev %d",
					debug_ip(state->ip_dst), iface);
			goto skip_redir_ifindex;
		}

		/* Revalidate the access to the packet */
		skb_refresh_start_end(ctx);
		if (ctx->data_start + sizeof(struct ethhdr) > ctx->data_end) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short");
			goto deny;
		}

		/* Patch in the MAC addresses that should be set on the next hop. */
		struct ethhdr *eth_hdr = ctx->data_start;
		__builtin_memcpy(&eth_hdr->h_dest, arpv->mac_dst, ETH_ALEN);
		__builtin_memcpy(&eth_hdr->h_source, arpv->mac_src, ETH_ALEN);

		rc = bpf_redirect(iface, 0);
		if (rc == TC_ACT_REDIRECT) {
			CALI_DEBUG("Redirect directly to interface (%d) succeeded.", iface);
			goto skip_fib;
		}

skip_redir_ifindex:
		CALI_DEBUG("Redirect directly to interface (%d) failed.", iface);
		/* fall through to FIB if enabled or the IP stack, don't give up yet. */
		rc = TC_ACT_UNSPEC;
#ifdef BPF_CORE_SUPPORTED
	} else if (CALI_F_FROM_HEP && bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_redirect_peer)) {
		bool redirect_peer = GLOBAL_FLAGS & CALI_GLOBALS_REDIRECT_PEER;

		if (redirect_peer && ct_result_rc(state->ct_result.rc) == CALI_CT_ESTABLISHED_BYPASS &&
			state->ct_result.ifindex_fwd != CT_INVALID_IFINDEX) {
			rc = bpf_redirect_peer(state->ct_result.ifindex_fwd, 0);
			if (rc == TC_ACT_REDIRECT) {
				CALI_DEBUG("Redirect to peer interface (%d) succeeded.", state->ct_result.ifindex_fwd);
				goto skip_fib;
			}
		}
#endif
	}

#if CALI_FIB_ENABLED
	/* Only do FIB for packets to be turned around at a HEP on HEP egress. */
	if (CALI_F_TO_HEP && !(ctx->state->flags & CALI_ST_CT_NP_LOOP)) {
		goto skip_fib;
	}

	// Try a short-circuit FIB lookup.
	if (fwd_fib(&ctx->fwd)) {
		/* Revalidate the access to the packet */
		if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short");
			goto deny;
		}

		/* Since we are going to short circuit the IP stack on
		 * forward, check if TTL is still alive. If not, let the
		 * IP stack handle it. It was approved by policy, so it
		 * is safe.
		 */
		if ip_ttl_exceeded(ip_hdr(ctx)) {
			rc = TC_ACT_UNSPEC;
			goto cancel_fib;
		}

		*fib_params(ctx) = (struct bpf_fib_lookup) {
#ifdef IPVER6
			.family = 10, /* AF_INET6 */
#else
			.family = 2, /* AF_INET */
#endif
			.tot_len = 0,
			.ifindex = CALI_F_TO_HOST ? ctx->skb->ingress_ifindex : ctx->skb->ifindex,
			.l4_protocol = state->ip_proto,
		};

		if (state->ip_proto != IPPROTO_ICMP_46) {
			fib_params(ctx)->sport = bpf_htons(state->sport);
			fib_params(ctx)->dport = bpf_htons(state->dport);
		}

		/* set the ipv4 here, otherwise the ipv4/6 unions do not get
		 * zeroed properly
		 */

#ifdef IPVER6
		ipv6_addr_t_to_be32_4_ip(fib_params(ctx)->ipv6_src, &state->ip_src);
		ipv6_addr_t_to_be32_4_ip(fib_params(ctx)->ipv6_dst, &state->ip_dst);
#else
		fib_params(ctx)->ipv4_src = state->ip_src;
		fib_params(ctx)->ipv4_dst = state->ip_dst;
#endif

		CALI_DEBUG("FIB family=%d", fib_params(ctx)->family);
		CALI_DEBUG("FIB ifindex=%d", fib_params(ctx)->ifindex);
		CALI_DEBUG("FIB l4_protocol=%d", fib_params(ctx)->l4_protocol);
		CALI_DEBUG("FIB sport=%d", bpf_ntohs(fib_params(ctx)->sport));
		CALI_DEBUG("FIB dport=%d", bpf_ntohs(fib_params(ctx)->dport));
#ifdef IPVER6
#else
		CALI_DEBUG("FIB ipv4_src=%x", bpf_ntohl(fib_params(ctx)->ipv4_src));
		CALI_DEBUG("FIB ipv4_dst=%x", bpf_ntohl(fib_params(ctx)->ipv4_dst));
#endif

		CALI_DEBUG("Traffic is towards the host namespace, doing Linux FIB lookup");
		rc = bpf_fib_lookup(ctx->skb, fib_params(ctx), sizeof(struct bpf_fib_lookup), ctx->fwd.fib_flags);
		switch (rc) {
		case 0:
			CALI_DEBUG("FIB lookup succeeded - with neigh");
			if (!fib_approve(ctx, fib_params(ctx)->ifindex)) {
				reason = CALI_REASON_WEP_NOT_READY;
				goto deny;
			}

			// Update the MACs.
			struct ethhdr *eth_hdr = ctx->data_start;
			__builtin_memcpy(&eth_hdr->h_source, fib_params(ctx)->smac, sizeof(eth_hdr->h_source));
			__builtin_memcpy(&eth_hdr->h_dest, fib_params(ctx)->dmac, sizeof(eth_hdr->h_dest));

			// Redirect the packet.
			CALI_DEBUG("Got Linux FIB hit, redirecting to iface %d.", fib_params(ctx)->ifindex);
			rc = bpf_redirect(fib_params(ctx)->ifindex, 0);

			break;

#ifdef BPF_CORE_SUPPORTED
		case BPF_FIB_LKUP_RET_NO_NEIGH:
			if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_redirect_neigh)) {
#ifdef IPVER6
				CALI_DEBUG("FIB lookup succeeded - no neigh - gw");
#else
				CALI_DEBUG("FIB lookup succeeded - no neigh - gw %x", bpf_ntohl(fib_params(ctx)->ipv4_dst));
#endif

				if (!fib_approve(ctx, fib_params(ctx)->ifindex)) {
					reason = CALI_REASON_WEP_NOT_READY;
					goto deny;
				}

				struct bpf_redir_neigh nh_params = {};

				nh_params.nh_family = fib_params(ctx)->family;
#ifdef IPVER6
				__builtin_memcpy(nh_params.ipv6_nh, fib_params(ctx)->ipv6_dst, sizeof(nh_params.ipv6_nh));
#else
				nh_params.ipv4_nh = fib_params(ctx)->ipv4_dst;
#endif

				CALI_DEBUG("Got Linux FIB hit, redirecting to iface %d.", fib_params(ctx)->ifindex);
				rc = bpf_redirect_neigh(fib_params(ctx)->ifindex, &nh_params, sizeof(nh_params), 0);
				break;
			} else {
				/* fallthrough to handling error */
			}
#endif /* BPF_CORE_SUPPORTED */

		default:
			if (rc < 0) {
				CALI_DEBUG("FIB lookup failed (bad input): %d.", rc);
				rc = TC_ACT_UNSPEC;
			} else {
				CALI_DEBUG("FIB lookup failed (FIB problem): %d.", rc);
				rc = TC_ACT_UNSPEC;
			}

			break;
		}

		/* now we know we will bypass IP stack and ip->ttl > 1, decrement it! */
		if (rc == TC_ACT_REDIRECT) {
#ifdef IPVER6
			ip_hdr(ctx)->hop_limit--;
#else
			ip_dec_ttl(ip_hdr(ctx));
#endif
		}
	}

cancel_fib:
#endif /* CALI_FIB_ENABLED */
	if (ctx->state->flags & CALI_ST_CT_NP_LOOP) {
		__u32 mark = CALI_SKB_MARK_SEEN;

		if (rc != TC_ACT_REDIRECT /* no FIB or failed */ ) {
			CALI_DEBUG("No FIB or failed, redirect to NATIF.");
			__u32 iface = NATIN_IFACE;

			struct arp_key arpk = {
				.ifindex = iface,
			};

			ip_set_void(arpk.ip);

			struct arp_value *arpv = cali_arp_lookup_elem(&arpk);
			if (!arpv) {
				ctx->fwd.reason = CALI_REASON_NATIFACE;
				CALI_DEBUG("ARP lookup failed for " IP_FMT " dev %d",
						debug_ip(state->ip_dst), iface);
				goto deny;
			}

			/* Revalidate the access to the packet */
			skb_refresh_start_end(ctx);
			if (ctx->data_start + sizeof(struct ethhdr) > ctx->data_end) {
				ctx->fwd.reason = CALI_REASON_SHORT;
				CALI_DEBUG("Too short");
				goto deny;
			}

			/* Patch in the MAC addresses that should be set on the next hop. */
			struct ethhdr *eth_hdr = ctx->data_start;
			__builtin_memcpy(&eth_hdr->h_dest, arpv->mac_dst, ETH_ALEN);
			__builtin_memcpy(&eth_hdr->h_source, arpv->mac_src, ETH_ALEN);

			rc = bpf_redirect(iface, 0);
			if (rc != TC_ACT_REDIRECT) {
				ctx->fwd.reason = CALI_REASON_NATIFACE;
				CALI_DEBUG("Redirect directly to bpfnatin failed.");
				goto deny;
			}

			CALI_DEBUG("Redirect directly to interface bpfnatin succeeded.");

			mark = CALI_SKB_MARK_BYPASS;

			if (ctx->state->flags & CALI_ST_CT_NP_REMOTE) {
				mark = CALI_SKB_MARK_BYPASS_FWD;
			}
		}

		CALI_DEBUG("Setting mark to 0x%x", mark);
		skb_set_mark(ctx->skb, mark);
	}

skip_fib:

	if (CALI_F_TO_HOST) {
		/* Packet is towards host namespace, mark it so that downstream
		 * programs know that they're not the first to see the packet.
		 */
		ctx->fwd.mark |=  CALI_SKB_MARK_SEEN;
		if (ctx->state->ct_result.flags & CALI_CT_FLAG_EXT_LOCAL) {
			CALI_DEBUG("To host marked with FLAG_EXT_LOCAL");
			ctx->fwd.mark |= EXT_TO_SVC_MARK;
			if (CALI_F_FROM_WEP && EXT_TO_SVC_MARK) {
				/* needs to go via normal routing unless we have access
				 * to BPF_FIB_LOOKUP_MARK in kernel 6.10+
				 */
				rc = TC_ACT_UNSPEC;
			}
		}

		if (CALI_F_NAT_IF) {
			/* We mark the packet so that next iface knows, it went through
			 * bpfnatout - if it gets (S)NATed, a new connection is created
			 * and we know that returning packets must go via bpfnatout again.
			 */
			ctx->fwd.mark |= CALI_SKB_MARK_FROM_NAT_IFACE_OUT;
			CALI_DEBUG("marking CALI_SKB_MARK_FROM_NAT_IFACE_OUT");
		}

		if (ct_result_is_related(state->ct_result.rc)) {
			CALI_DEBUG("Related traffic, marking with CALI_SKB_MARK_RELATED_RESOLVED");
			ctx->fwd.mark |= CALI_SKB_MARK_RELATED_RESOLVED;
		}

		CALI_DEBUG("Traffic is towards host namespace, marking with 0x%x.", ctx->fwd.mark);

		/* FIXME: this ignores the mask that we should be using.
		 * However, if we mask off the bits, then clang spots that it
		 * can do a 16-bit store instead of a 32-bit load/modify/store,
		 * which trips up the validator.
		 */
		skb_set_mark(ctx->skb, ctx->fwd.mark); /* make sure that each pkt has SEEN mark */
	}

	goto allow;

deny:
	rc =  TC_ACT_SHOT;

allow:
	if (CALI_LOG_LEVEL_INFO >= CALI_LOG_LEVEL_INFO || PROFILING) {
		__u64 prog_end_time = bpf_ktime_get_ns();

		if (PROFILING) {
			prof_record_sample(ctx->skb->ifindex,
				(CALI_F_FROM_HEP || CALI_F_TO_WEP ? 0 : 2) +
					(ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_NEW ? 0 : 1),
				state->prog_start_time, prog_end_time);
		}

		if (rc ==  TC_ACT_SHOT) {
			CALI_INFO("Final result=DENY (%d). Program execution time: %lluns",
					reason, prog_end_time-state->prog_start_time);
		} else {
			CALI_INFO("Final result=ALLOW (%d). Program execution time: %lluns",
					reason, prog_end_time-state->prog_start_time);
		}
	}

	return rc;
}

#endif /* __CALI_FIB_H__ */
