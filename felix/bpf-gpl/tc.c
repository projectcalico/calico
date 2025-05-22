// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "tc.h"

/* calico_tc_main is the main function used in all of the tc programs.  It is specialised
 * for particular hook at build time based on the CALI_F build flags.
 */
SEC("tc")
int calico_tc_main(struct __sk_buff *skb)
{
#ifdef UNITTEST
	/* UT-only workaround to allow us to run the program with BPF_TEST_PROG_RUN
	 * and simulate a specific mark
	 */
	skb->mark = SKB_MARK;
#endif

	if (CALI_F_LO && CALI_F_TO_HOST) {
		/* Do nothing, it is a packet that just looped around. */
		return TC_ACT_UNSPEC;
	}

	/* Optimisation: if another BPF program has already pre-approved the packet,
	 * skip all processing. */
	if (CALI_F_FROM_HOST && skb->mark == CALI_SKB_MARK_BYPASS) {
		if  (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_DEBUG) {
			/* This generates a bit more richer output for logging */
			DECLARE_TC_CTX(_ctx,
				.skb = skb,
				.fwd = {
					.res = TC_ACT_UNSPEC,
					.reason = CALI_REASON_UNKNOWN,
				},
				.ipheader_len = IP_SIZE,
			);
			struct cali_tc_ctx *ctx = &_ctx;

			CALI_DEBUG("New packet at ifindex=%d; mark=%x", skb->ifindex, skb->mark);
			parse_packet_ip(ctx);
			CALI_DEBUG("Final result=ALLOW (%d). Bypass mark set.", CALI_REASON_BYPASS);
		}
		return TC_ACT_UNSPEC;
	}

	if (CALI_F_NAT_IF) {
		switch (skb->mark) {
		case CALI_SKB_MARK_BYPASS:
			/* We are turning a packet around to a local WEP using bpfnat
			 * iface, the WEP should do normal processing.
			 */
			skb->mark = 0UL;
			CALI_LOG_IF(CALI_LOG_LEVEL_INFO,
				"Final result=ALLOW (%d). Bypass mark set at bpfnat local WL", CALI_REASON_BYPASS);
			return TC_ACT_UNSPEC;
		case CALI_SKB_MARK_BYPASS_FWD:
			/* We are turning a packet around from lo to a remote WEP using
			 * bpfnat iface. Next hop is a HEP and it should just forward the
			 * packet.
			 */
			{
				__u32 mark = CALI_SKB_MARK_BYPASS;
				skb->mark = mark;
			}
			CALI_LOG_IF(CALI_LOG_LEVEL_INFO,
				"Final result=ALLOW (%d). Bypass mark set at bpfnat remote WL", CALI_REASON_BYPASS);
			return TC_ACT_UNSPEC;
		}
	}

	/* Optimisation: if XDP program has already accepted the packet,
	 * skip all processing. */
	if (CALI_F_FROM_HEP) {
		if (xdp2tc_get_metadata(skb) & CALI_META_ACCEPTED_BY_XDP) {
			CALI_LOG_IF(CALI_LOG_LEVEL_INFO,
					"Final result=ALLOW (%d). Accepted by XDP.", CALI_REASON_ACCEPTED_BY_XDP);
			skb->mark = CALI_SKB_MARK_BYPASS_XDP;
			return TC_ACT_UNSPEC;
		}
	}

	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
		.ipheader_len = IP_SIZE,
	);

	struct cali_tc_ctx *ctx = &_ctx;

	__builtin_memset(ctx->state, 0, sizeof(*ctx->state));

	CALI_DEBUG("New packet at ifindex=%d; mark=%x", skb->ifindex, skb->mark);

	counter_inc(ctx, COUNTER_TOTAL_PACKETS);

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO || PROFILING) {
		ctx->state->prog_start_time = bpf_ktime_get_ns();
	}

	/* We only try a FIB lookup and redirect for packets that are towards the host.
	 * For packets that are leaving the host namespace, routing has already been done. */
	fwd_fib_set(&ctx->fwd, CALI_F_TO_HOST);

	if (CALI_F_TO_HEP || CALI_F_TO_WEP) {
		/* We're leaving the host namespace, check for other bypass mark bits.
		 * These are a bit more complex to handle so we do it after creating the
		 * context/state. */
		switch (skb->mark & CALI_SKB_MARK_BYPASS_MASK) {
		case CALI_SKB_MARK_BYPASS_FWD:
			CALI_DEBUG("Packet approved for forward.");
			counter_inc(ctx, CALI_REASON_BYPASS);
			goto allow;
		}
	}

	/* Parse the packet as far as the IP header; as a side-effect this validates the packet size
	 * is large enough for UDP. */
	switch (parse_packet_ip(ctx)) {
#ifdef IPVER6
	case PARSING_OK_V6:
		// IPv6 Packet.
		break;
#else
	case PARSING_OK:
		// IPv4 Packet.
		break;
#endif
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		// A packet that we automatically let through
		fwd_fib_set(&ctx->fwd, false);
		ctx->fwd.res = TC_ACT_UNSPEC;
		goto finalize;
	case PARSING_ERROR:
	default:
		// A malformed packet or a packet we don't support
		CALI_DEBUG("Drop malformed or unsupported packet");
		ctx->fwd.res = TC_ACT_SHOT;
		goto finalize;
	}

#ifndef IPVER6
	if (CALI_F_TO_HOST && ip_is_frag(ip_hdr(ctx))) {
		CALI_JUMP_TO(ctx, PROG_INDEX_IP_FRAG);
		goto deny;
	}
#endif

	return pre_policy_processing(ctx);

allow:
finalize:
	return forward_or_drop(ctx);

#ifndef IPVER6
deny:
	ctx->fwd.res = TC_ACT_SHOT;
	goto finalize;
#endif
}

SEC("tc")
int calico_tc_skb_accepted_entrypoint(struct __sk_buff *skb)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
			.mark = CALI_SKB_MARK_SEEN,
		},
	);
	struct cali_tc_ctx *ctx = &_ctx;
	bool policy_skipped = ctx->state->flags & CALI_ST_SKIP_POLICY;

	CALI_DEBUG("Entering calico_tc_skb_accepted_entrypoint");

	if (!policy_skipped) {
		counter_inc(ctx, CALI_REASON_ACCEPTED_BY_POLICY);
		if (CALI_F_TO_WEP && ctx->skb->mark == CALI_SKB_MARK_MASQ) {
			/* Restore state->ip_src */
			CALI_DEBUG("Accepted MASQ to self - restoring source for conntrack.");
			ctx->state->ip_src = ctx->state->ip_src_masq;
		}
	}

	if (CALI_F_HEP) {
		if (!policy_skipped && (ctx->state->flags & CALI_ST_SUPPRESS_CT_STATE)) {
			// See comment above where CALI_ST_SUPPRESS_CT_STATE is set.
			CALI_DEBUG("Egress HEP should drop packet with no CT state");
			return TC_ACT_SHOT;
		}
	}

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short");
		goto deny;
	}

	if (!policy_skipped) {
		if (FLOWLOGS_ENABLED) {
			event_flow_log(ctx);
			CALI_DEBUG("Flow log event generated for ALLOW\n");
		}
		update_rule_counters(ctx);
		skb_log(ctx, true);
	}

#ifndef IPVER6
	if (CALI_F_FROM_HOST && ip_is_first_frag(ip_hdr(ctx))) {
		frags4_record_ct(ctx);
	}
#endif

	ctx->fwd = calico_tc_skb_accepted(ctx);
	return forward_or_drop(ctx);

deny:
	return TC_ACT_SHOT;
}

SEC("tc")
int calico_tc_skb_new_flow_entrypoint(struct __sk_buff *skb)
{
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
			.mark = CALI_SKB_MARK_SEEN,
		},
	);
	struct cali_tc_ctx *ctx = &_ctx;
	struct cali_tc_state *state = ctx->state;
	enum do_nat_res nat_res = NAT_ALLOW;
	bool is_dnat = false;
	__u32 seen_mark = ctx->fwd.mark;
	bool fib = true;

	CALI_DEBUG("Entering calico_tc_skb_new_flow");

	switch (state->pol_rc) {
	case CALI_POL_NO_MATCH:
		CALI_DEBUG("Implicitly denied by policy: DROP");
		goto deny;
	case CALI_POL_DENY:
		CALI_DEBUG("Denied by policy: DROP");
		goto deny;
	case CALI_POL_ALLOW:
		CALI_DEBUG("Allowed by policy: ACCEPT");
	}

	if (CALI_F_FROM_WEP &&
			CALI_DROP_WORKLOAD_TO_HOST &&
			cali_rt_flags_local_host(
				cali_rt_lookup_flags(&state->post_nat_ip_dst))) {
		CALI_DEBUG("Workload to host traffic blocked by "
			   "DefaultEndpointToHostAction: DROP");
		goto deny;
	}

	update_fib_mark(state, &fib, &seen_mark);

	struct ct_create_ctx *ct_ctx_nat = &ctx->scratch->ct_ctx_nat;
	__builtin_memset(ct_ctx_nat, 0, sizeof(*ct_ctx_nat));

	ct_ctx_nat->proto = state->ip_proto;
	ct_ctx_nat->src = state->ip_src;
	ct_ctx_nat->sport = state->sport;
	ct_ctx_nat->dst = state->post_nat_ip_dst;
	ct_ctx_nat->dport = state->post_nat_dport;
	ct_ctx_nat->tun_ip = state->tun_ip;
	ct_ctx_nat->type = CALI_CT_TYPE_NORMAL;
	ct_ctx_nat->allow_return = false;
	if (state->flags & CALI_ST_NAT_OUTGOING) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_NAT_OUT;
	}
	if (CALI_F_TO_HOST && state->flags & CALI_ST_SKIP_FIB) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_SKIP_FIB;
	}
	if (state->flags & CALI_ST_SKIP_REDIR_PEER) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_SKIP_REDIR_PEER;
	}
	if (CALI_F_TO_WEP) {
		if (!(ctx->skb->mark & CALI_SKB_MARK_SEEN)) {
			/* If the packet wasn't seen, must come from host. There is no
			 * need to do FIB lookup for returning traffic. In fact, it may
			 * not be always correct, e.g. when some mesh and custom iptables
			 * rules are used by the host. So don't mess with it.
			 */
			ct_ctx_nat->flags |= CALI_CT_FLAG_SKIP_FIB;
		} else if ((ctx->skb->mark & CALI_SKB_MARK_SKIP_FIB) == CALI_SKB_MARK_SKIP_FIB) {
			/* Packets received at WEP with CALI_CT_FLAG_SKIP_FIB mark signal
			 * that all traffic on this connection must flow via host
			 * namespace as it was originally meant for host, but got
			 * redirected to a WEP by a 3rd party DNAT rule.
			 */
			ct_ctx_nat->flags |= CALI_CT_FLAG_SKIP_FIB;
		}
	}
	if (CALI_F_TO_HOST && CALI_F_NAT_IF) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_VIA_NAT_IF;
	}
	if (CALI_F_TO_HEP && !CALI_F_NAT_IF && state->flags & CALI_ST_CT_NP_LOOP) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_NP_LOOP;
	}
	if (CALI_F_TO_HEP && !CALI_F_NAT_IF && state->flags & CALI_ST_CT_NP_REMOTE) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_NP_REMOTE;
	}
	if (state->flags & CALI_ST_HOST_PSNAT) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_HOST_PSNAT;
	}
	/* Mark connections that were routed via bpfnatout, but had CT miss at
	 * HEP. That is because of SNAT happened between bpfnatout and here.
	 * Returning packets on such a connection must go back via natbpfout
	 * without a short-circuit to reverse the service NAT.
	 */
	if (CALI_F_TO_HEP &&
			((ctx->skb->mark & CALI_SKB_MARK_FROM_NAT_IFACE_OUT) == CALI_SKB_MARK_FROM_NAT_IFACE_OUT)) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_VIA_NAT_IF;
	}

	/* If we just received the first packet for a NP forwarded from a
	 * different node via a tunnel and we are in DSR mode and there are optout
	 * CIDRs from DSR, we need to make a check if this client also opted out
	 * and save the information in conntrack.
	 */
	if (CALI_F_FROM_HEP && CALI_F_DSR && (GLOBAL_FLAGS & CALI_GLOBALS_NO_DSR_CIDRS)) {
		CALI_DEBUG("state->tun_ip = " IP_FMT "", debug_ip(state->tun_ip));
		if (!ip_void(state->tun_ip) && cali_rt_lookup_flags(&state->ip_src) & CALI_RT_NO_DSR) {
			ct_ctx_nat->flags |= CALI_CT_FLAG_NP_NO_DSR;
			CALI_DEBUG("CALI_CT_FLAG_NP_NO_DSR");
		}
	}

	if (state->ip_proto == IPPROTO_TCP) {
		if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short for TCP: DROP");
			goto deny;
		}
		ct_ctx_nat->tcp = tcp_hdr(ctx);
	}

	// If we get here, we've passed policy.

	if (ip_void(ctx->state->nat_dest.addr)) {
		if (conntrack_create(ctx, ct_ctx_nat)) {
			CALI_DEBUG("Creating normal conntrack failed");

			if ((CALI_F_FROM_HEP && rt_addr_is_local_host(&ct_ctx_nat->dst)) ||
					(CALI_F_TO_HEP && rt_addr_is_local_host(&ct_ctx_nat->src))) {
				CALI_DEBUG("Allowing local host traffic without CT");
				goto allow;
			}
			deny_reason(ctx, CALI_REASON_CT_CREATE_FAILED);
			goto deny;
		}
		goto allow;
	}

	ct_ctx_nat->orig_src = state->ip_src;
	ct_ctx_nat->orig_dst = state->ip_dst;
	ct_ctx_nat->orig_dport = state->dport;
	ct_ctx_nat->orig_sport = state->sport;
	state->ct_result.nat_sport = ct_ctx_nat->sport;
	/* fall through as DNAT is now established */

	if ((CALI_F_TO_HOST && CALI_F_NAT_IF) || (CALI_F_TO_HEP && (CALI_F_LO || CALI_F_MAIN))) {
		struct cali_rt *r = cali_rt_lookup(&state->post_nat_ip_dst);
		if (r && cali_rt_flags_remote_workload(r->flags) && cali_rt_is_tunneled(r)) {
			CALI_DEBUG("remote wl " IP_FMT " tunneled via " IP_FMT "",
					debug_ip(state->post_nat_ip_dst), debug_ip(HOST_TUNNEL_IP));
			ct_ctx_nat->src = HOST_TUNNEL_IP;
			/* This would be the place to set a new source port if we
			 * had a way how to allocate it. Instead we rely on source
			 * port collision resolution.
			 * ct_ctx_nat->sport = 10101;
			 */
			state->ct_result.nat_sip = ct_ctx_nat->src;
			state->ct_result.nat_sport = ct_ctx_nat->sport;
		}
	}

	size_t l4_csum_off = 0;

	switch (ctx->state->ip_proto) {
	case IPPROTO_TCP:
		l4_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct tcphdr, check);
		break;
	case IPPROTO_UDP:
		l4_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct udphdr, check);
		break;
	}

	/* Only do the refresh if we get here */
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short");
		goto deny;
	}

	nat_res = do_nat(ctx, skb_iphdr_offset(ctx), l4_csum_off, false,
			 CALI_CT_NEW, ct_ctx_nat, &is_dnat, &seen_mark, false);
	if (nat_res == NAT_ICMP_TOO_BIG) {
		goto icmp_send_reply;
	}

allow:
do_post_nat:
	ctx->fwd = post_nat(ctx, nat_res, fib, seen_mark, is_dnat);
	return forward_or_drop(ctx);

icmp_send_reply:
	CALI_JUMP_TO(ctx, PROG_INDEX_ICMP);
	goto deny;

deny:
	nat_res = NAT_DENY;
	goto do_post_nat;
}

SEC("tc")
int calico_tc_skb_icmp_inner_nat(struct __sk_buff *skb)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	);
	struct cali_tc_ctx *ctx = &_ctx;

	struct cali_tc_state *state = ctx->state;
	bool ct_related = ct_result_is_related(state->ct_result.rc);
	int ct_rc = ct_result_rc(state->ct_result.rc);

	CALI_DEBUG("Entering calico_tc_skb_icmp_inner_nat");

	if (!ct_related) {
		CALI_DEBUG("ICMP: unexpected unrelated");
		goto deny;
	}

	/* Start parsing the packet again to get what is the outer IP header size */

	switch (parse_packet_ip(ctx)) {
#ifdef IPVER6
	case PARSING_OK_V6:
		// IPv6 Packet.
		break;
#else
	case PARSING_OK:
		// IPv4 Packet.
		break;
#endif
	default:
		// A malformed packet or a packet we don't support
		CALI_DEBUG("ICMP: Drop malformed or unsupported packet");
		ctx->fwd.res = TC_ACT_SHOT;
		goto deny;
	}

	size_t icmp_csum_off = 0;

#ifdef IPVER6
	icmp_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct icmp6hdr, icmp6_cksum);
#else
	icmp_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct icmphdr, checksum);
#endif

	__u8 pkt[IP_SIZE] = { /* zero it to shut up verifier */ };
	__u8 l4pkt[8 /* what must be there */] = {};

	ctx->ip_header = (struct iphdr*)pkt;
	ctx->nh = (void *)l4pkt;

	int inner_ip_offset = skb_l4hdr_offset(ctx) + ICMP_SIZE;

	if (bpf_skb_load_bytes(ctx->skb, inner_ip_offset, pkt, IP_SIZE)) {
		CALI_DEBUG("Too short");
		goto deny;
	}

#ifdef IPVER6
	tc_state_fill_from_iphdr_v6_offset(ctx, inner_ip_offset);
#else
	tc_state_fill_from_iphdr_v4(ctx);
#endif

	if (bpf_skb_load_bytes(ctx->skb, inner_ip_offset + ctx->ipheader_len, l4pkt , 8)) {
		CALI_DEBUG("Too short");
		goto deny;
	}

	/* Flip the direction, we need to reverse the original packet. */
	switch (ct_rc) {
		case CALI_CT_ESTABLISHED_SNAT:
			/* handle the DSR case, see CALI_CT_ESTABLISHED_SNAT where nat is done */
			if (dnat_return_should_encap() && !ip_void(state->ct_result.tun_ip)) {
				if (CALI_F_DSR) {
					/* SNAT will be done after routing, when leaving HEP */
					CALI_DEBUG("DSR enabled, skipping SNAT + encap");
					/* Don't treat it as related anymore as we defer
					 * that. This will not set CALI_SKB_MARK_RELATED_RESOLVED
					 */
					ct_result_clear_flag(STATE->ct_result.rc, CT_RES_RELATED);
					goto allow;
				}
			}
			ct_rc = CALI_CT_ESTABLISHED_DNAT;
			break;
		case CALI_CT_ESTABLISHED_DNAT:
			if (CALI_F_FROM_HEP && !ip_void(state->tun_ip) && ct_result_np_node(state->ct_result)) {
				/* Packet is returning from a NAT tunnel, just forward it. */
				ctx->fwd.mark = CALI_SKB_MARK_BYPASS_FWD;
				CALI_DEBUG("ICMP related returned from NAT tunnel");
				goto allow;
			}
			ct_rc = CALI_CT_ESTABLISHED_SNAT;
			break;
	}

	bool is_dnat = false;
	enum do_nat_res nat_res = NAT_ALLOW;
	__u32 seen_mark = ctx->fwd.mark;
	bool fib = true;

	nat_res = do_nat(ctx, inner_ip_offset, icmp_csum_off, false, ct_rc, NULL, &is_dnat, &seen_mark, true);
	ctx->fwd = post_nat(ctx, nat_res, fib, seen_mark, is_dnat);

allow:
	/* We are going to forward the packet now. But all the state is about
	 * the inner IP so we need to refresh our state back to the outer IP
	 * that is used for forwarding!
	 *
	 * N.B. we could just remember an update the state, however, forwarding
	 * also updates ttl/hops in the header so we need the right header
	 * available anyway.
	 */
#ifdef IPVER6
	if (parse_packet_ip(ctx) != PARSING_OK_V6) {
#else
	if (parse_packet_ip(ctx) != PARSING_OK) {
#endif
		CALI_DEBUG("Non ipv4 packet on icmp path! DROP!");
		goto deny;
	}
	tc_state_fill_from_iphdr(ctx);
	fwd_fib_set(&ctx->fwd, true);

	return forward_or_drop(ctx);

deny:
	return TC_ACT_SHOT;
}


SEC("tc")
int calico_tc_skb_send_icmp_replies(struct __sk_buff *skb)
{
	__u32 fib_flags = 0;

	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	);
	struct cali_tc_ctx *ctx = &_ctx;

	CALI_DEBUG("Entering calico_tc_skb_send_icmp_replies");
	CALI_DEBUG("ICMP type %d and code %d",ctx->state->icmp_type, ctx->state->icmp_code);

#ifdef IPVER6
	if (ctx->state->icmp_code == ICMPV6_PKT_TOOBIG) {
#else
	if (ctx->state->icmp_code == ICMP_FRAG_NEEDED) {
#endif
		fib_flags |= BPF_FIB_LOOKUP_OUTPUT;
		if (CALI_F_FROM_WEP) {
			/* we know it came from workload, just send it back the same way */
			ctx->fwd.res = CALI_RES_REDIR_BACK;
		}
	}

	if (icmp_reply(ctx, ctx->state->icmp_type, ctx->state->icmp_code, ctx->state->icmp_un)) {
		ctx->fwd.res = TC_ACT_SHOT;
	} else {
		ctx->fwd.mark = CALI_SKB_MARK_BYPASS_FWD;

		fwd_fib_set(&ctx->fwd, false);
		fwd_fib_set_flags(&ctx->fwd, fib_flags);
	}

	if (skb_refresh_validate_ptrs(ctx, ICMP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short");
		goto deny;
	}

	tc_state_fill_from_iphdr(ctx);
	ctx->state->sport = ctx->state->dport = 0;
	return forward_or_drop(ctx);
deny:
	(void)fib_flags;
	return TC_ACT_SHOT;
}

#if HAS_HOST_CONFLICT_PROG
SEC("tc")
int calico_tc_host_ct_conflict(struct __sk_buff *skb)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	);

	struct cali_tc_ctx *ctx = &_ctx;

	struct calico_nat_dest nat_dest_ident;

	CALI_DEBUG("Entering calico_tc_host_ct_conflict_entrypoint");

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short");
		goto deny;
	}

	__u16 sport = ctx->state->sport;
	ctx->state->sport = 0;
	ctx->state->ct_result = calico_ct_lookup(ctx);
	ctx->state->sport = sport;
	ctx->state->flags |= CALI_ST_HOST_PSNAT;

	switch (ct_result_rc(ctx->state->ct_result.rc)) {
	case CALI_CT_ESTABLISHED:
		/* Because we are on the "from host" path, conntrack may give us
		 * CALI_CT_ESTABLISHED only if traffic targets pod without DNAT. Better to
		 * fix the corner case here than on the generic path.
		 */
		ct_result_set_rc(ctx->state->ct_result.rc, CALI_CT_ESTABLISHED_DNAT);
		/* fallthrough */
	case CALI_CT_NEW:
		/* There is a conflict, this is the first packet that conflicts. By
		 * setting a NAT destination being the same as the original destination,
		 * we trigger a void/fake DNAT which will conflict on the source
		 * port and will trigger psnat.
		 */
		nat_dest_ident.addr = ctx->state->ip_dst;
		nat_dest_ident.port = ctx->state->dport;

		ctx->nat_dest = &nat_dest_ident;
		break;
	default:
		CALI_INFO("Unexpected CT result %d after host source port collision DENY.",
			  ct_result_rc(ctx->state->ct_result.rc));
		goto deny;
	}

	calico_tc_process_ct_lookup(ctx);

	return forward_or_drop(ctx);

deny:
	return TC_ACT_SHOT;
}
#endif /* HAS_HOST_CONFLICT_PROG */

SEC("tc")
int calico_tc_skb_drop(struct __sk_buff *skb)
{
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
	);
	struct cali_tc_ctx *ctx = &_ctx;

	CALI_DEBUG("Entering calico_tc_skb_drop");

	update_rule_counters(ctx);
	skb_log(ctx, false);
	counter_inc(ctx, CALI_REASON_DROPPED_BY_POLICY);

	CALI_DEBUG("proto=%d", ctx->state->ip_proto);
	CALI_DEBUG("src=" IP_FMT " dst=" IP_FMT "", debug_ip(ctx->state->ip_src),
			debug_ip(ctx->state->ip_dst));
	CALI_DEBUG("pre_nat=" IP_FMT ":%d", debug_ip(ctx->state->pre_nat_ip_dst),
			ctx->state->pre_nat_dport);
	CALI_DEBUG("post_nat=" IP_FMT ":%d", debug_ip(ctx->state->post_nat_ip_dst), ctx->state->post_nat_dport);
	CALI_DEBUG("tun_ip=" IP_FMT "", debug_ip(ctx->state->tun_ip));
	CALI_DEBUG("pol_rc=%d", ctx->state->pol_rc);
	CALI_DEBUG("sport=%d", ctx->state->sport);
	CALI_DEBUG("flags=0x%x", ctx->state->flags);
	CALI_DEBUG("ct_rc=%d", ctx->state->ct_result.rc);

	/* This is a policy override for Wireguard traffic. It is regular UDP
	 * traffic on known ports between known hosts. We want to let this
	 * traffic through so that a user does not shoot him/herself in a foot
	 * by blocking this traffic by a HEP policy.
	 *
	 * If such traffic is allowed here, it will create regular CT entry and
	 * thus every subsequent packet will save itself the trouble of going
	 * through policy and ending up here over and over again.
	 */
	if (CALI_F_HEP &&
			ctx->state->ip_proto == IPPROTO_UDP &&
			ctx->state->pre_nat_dport == ctx->state->post_nat_dport &&
			ctx->state->pre_nat_dport == WG_PORT &&
			ctx->state->sport == WG_PORT) {
		if ((CALI_F_FROM_HEP &&
				rt_addr_is_local_host(&ctx->state->ip_dst) &&
				rt_addr_is_remote_host(&ctx->state->ip_src)) ||
			(CALI_F_TO_HEP &&
				rt_addr_is_remote_host(&ctx->state->ip_dst) &&
				rt_addr_is_local_host(&ctx->state->ip_src))) {
			/* This is info as it is supposed to be low intensity (only when a
			 * new flow detected - should happen exactly once in a blue moon ;-) )
			 * but would be good to know about for issue debugging.
			 */
			CALI_INFO("Allowing WG " IP_FMT " <-> " IP_FMT " despite blocked by policy - known hosts.",
					debug_ip(ctx->state->ip_src), debug_ip(ctx->state->ip_dst));
			goto allow;
		}
	}

	if (FLOWLOGS_ENABLED) {
		event_flow_log(ctx);
		CALI_DEBUG("Flow log event generated for DENY/DROP\n");
	}
	goto deny;

allow:
	ctx->state->pol_rc = CALI_POL_ALLOW;
	ctx->state->flags |= CALI_ST_SKIP_POLICY;
	ctx->state->rules_hit = 0;

	CALI_JUMP_TO(ctx, PROG_INDEX_ALLOWED);
	/* should not reach here */
	CALI_DEBUG("Failed to jump to allow program.");

deny:
	CALI_DEBUG("DENY due to policy");
	return TC_ACT_SHOT;
}

#ifndef IPVER6
SEC("tc")
int calico_tc_skb_ipv4_frag(struct __sk_buff *skb)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	DECLARE_TC_CTX(_ctx,
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	);
	struct cali_tc_ctx *ctx = &_ctx;

	CALI_DEBUG("Entering calico_tc_skb_ipv4_frag");
	CALI_DEBUG("iphdr_offset %d ihl %d", skb_iphdr_offset(ctx), ctx->ipheader_len);

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short");
		goto deny;
	}

	tc_state_fill_from_iphdr_v4(ctx);

	if (!frags4_handle(ctx)) {
		deny_reason(ctx, CALI_REASON_FRAG_WAIT);
		goto deny;
	}
	/* force it through stack to trigger any further necessary fragmentation */
	ctx->state->flags |= CALI_ST_SKIP_REDIR_ONCE;

	return pre_policy_processing(ctx);

finalize:
	return forward_or_drop(ctx);

deny:
	ctx->fwd.res = TC_ACT_SHOT;
	goto finalize;
}
#endif /* !IPVER6 */
