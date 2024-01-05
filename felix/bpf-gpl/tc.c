// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>


#include "bpf.h"
#include "types.h"
#include "counters.h"
#include "log.h"
#include "skb.h"
#include "policy.h"
#include "conntrack.h"
#include "nat.h"
#include "nat_lookup.h"
#include "routes.h"
#include "jump.h"
#include "reasons.h"
#include "icmp.h"
#include "arp.h"
#include "sendrecv.h"
#include "fib.h"
#include "rpf.h"
#include "parsing.h"
#include "tc.h"
#include "failsafe.h"
#include "metadata.h"
#include "bpf_helpers.h"
#include "rule_counters.h"

#define HAS_HOST_CONFLICT_PROG CALI_F_TO_HEP

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

			CALI_DEBUG("New packet at ifindex=%d; mark=%x\n", skb->ifindex, skb->mark);
			parse_packet_ip(ctx);
			CALI_DEBUG("Final result=ALLOW (%d). Bypass mark set.\n", CALI_REASON_BYPASS);
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
				"Final result=ALLOW (%d). Bypass mark set at bpfnat local WL\n", CALI_REASON_BYPASS);
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
				"Final result=ALLOW (%d). Bypass mark set at bpfnat remote WL\n", CALI_REASON_BYPASS);
			return TC_ACT_UNSPEC;
		}
	}

	/* Optimisation: if XDP program has already accepted the packet,
	 * skip all processing. */
	if (CALI_F_FROM_HEP) {
		if (xdp2tc_get_metadata(skb) & CALI_META_ACCEPTED_BY_XDP) {
			CALI_LOG_IF(CALI_LOG_LEVEL_INFO,
					"Final result=ALLOW (%d). Accepted by XDP.\n", CALI_REASON_ACCEPTED_BY_XDP);
			skb->mark = CALI_SKB_MARK_BYPASS;
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

	CALI_DEBUG("New packet at ifindex=%d; mark=%x\n", skb->ifindex, skb->mark);

	counter_inc(ctx, COUNTER_TOTAL_PACKETS);

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
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
			CALI_DEBUG("Packet approved for forward.\n");
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
		CALI_DEBUG("Drop malformed or unsupported packet\n");
		ctx->fwd.res = TC_ACT_SHOT;
		goto finalize;
	}
	return pre_policy_processing(ctx);

allow:
finalize:
	return forward_or_drop(ctx);
}

static CALI_BPF_INLINE int pre_policy_processing(struct cali_tc_ctx *ctx)
{
	/* Copy fields that are needed by downstream programs from the packet to the state. */
	tc_state_fill_from_iphdr(ctx);

	if (CALI_F_LO && (GLOBAL_FLAGS & CALI_GLOBALS_LO_UDP_ONLY) && ctx->state->ip_proto != IPPROTO_UDP) {
		CALI_DEBUG("Allowing because it is not UDP\n");
		goto allow;
	}

	/* Parse out the source/dest ports (or type/code for ICMP). */
	switch (tc_state_fill_from_nexthdr(ctx, dnat_should_decap())) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	/* Now we've got as far as the UDP header, check if this is one of our VXLAN packets, which we
	 * use to forward traffic for node ports. */
	if (dnat_should_decap() /* Compile time: is this a BPF program that should decap packets? */ &&
			is_vxlan_tunnel(ctx, VXLAN_PORT) /* Is this a VXLAN packet? */ ) {
		/* Decap it; vxlan_attempt_decap will revalidate the packet if needed. */
		switch (vxlan_attempt_decap(ctx)) {
		case -1:
			/* Problem decoding the packet. */
			goto deny;
		case -2:
			/* Non-BPF VXLAN packet from another Calico node. */
			CALI_DEBUG("VXLAN packet from known Calico host, allow.\n");
			fwd_fib_set(&(ctx->fwd), false);
			goto allow;
		}

		/* Again, copy fields that are needed by downstream programs from the
		 * packet to the state after we unpacked the inner packet.
		 */
		tc_state_fill_from_iphdr(ctx);
		/* Parse out the source/dest ports (or type/code for ICMP). */
		switch (tc_state_fill_from_nexthdr(ctx, dnat_should_decap())) {
		case PARSING_ERROR:
			goto deny;
		case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
			goto allow;
		}
	}

	ctx->state->pol_rc = CALI_POL_NO_MATCH;

	/* Do conntrack lookup before anything else */
	ctx->state->ct_result = calico_ct_lookup(ctx);

	calico_tc_process_ct_lookup(ctx);

allow:
finalize:
	return forward_or_drop(ctx);
deny:
	ctx->fwd.res = TC_ACT_SHOT;
	goto finalize;
}

static CALI_BPF_INLINE void calico_tc_process_ct_lookup(struct cali_tc_ctx *ctx)
{
	CALI_DEBUG("conntrack entry flags 0x%x\n", ctx->state->ct_result.flags);

	/* We are forwarding a packet if it has a seen mark (that is another
	 * program has seen it already) and is either not routed through the
	 * bpfnat iface (which may be true for host traffic) or has the specific
	 * reasons set.
	 */
	bool forwarding = CALI_F_EGRESS &&
		skb_mark_equals(ctx->skb, CALI_SKB_MARK_SEEN_MASK, CALI_SKB_MARK_SEEN) &&
		(!skb_mark_equals(ctx->skb, CALI_SKB_MARK_FROM_NAT_IFACE_OUT, CALI_SKB_MARK_FROM_NAT_IFACE_OUT) ||
		 (skb_mark_equals(ctx->skb, CALI_SKB_MARK_BYPASS_MASK, CALI_SKB_MARK_FALLTHROUGH) ||
		  skb_mark_equals(ctx->skb, CALI_SKB_MARK_BYPASS_MASK, CALI_SKB_MARK_NAT_OUT) ||
		  skb_mark_equals(ctx->skb, CALI_SKB_MARK_BYPASS_MASK, CALI_SKB_MARK_MASQ) ||
		  skb_mark_equals(ctx->skb, CALI_SKB_MARK_BYPASS_MASK, CALI_SKB_MARK_SKIP_FIB)));

	if (HAS_HOST_CONFLICT_PROG &&
			(ctx->state->ct_result.flags & CALI_CT_FLAG_VIA_NAT_IF) &&
			!(ctx->skb->mark & (CALI_SKB_MARK_FROM_NAT_IFACE_OUT | CALI_SKB_MARK_SEEN))) {
		CALI_DEBUG("Host source SNAT conflict\n");
		CALI_JUMP_TO(ctx, PROG_INDEX_HOST_CT_CONFLICT);
		CALI_DEBUG("Failed to call conflict resolution.\n");
		goto deny;
	}

	/* Check if someone is trying to spoof a tunnel packet */
	if (CALI_F_FROM_HEP && ct_result_tun_src_changed(ctx->state->ct_result.rc)) {
		CALI_DEBUG("dropping tunnel pkt with changed source node\n");
		goto deny;
	}

	if (ctx->state->ct_result.flags & CALI_CT_FLAG_NAT_OUT) {
		ctx->state->flags |= CALI_ST_NAT_OUTGOING;
	}

	if (CALI_F_TO_HOST && !CALI_F_NAT_IF &&
			(ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_ESTABLISHED ||
			 ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_ESTABLISHED_BYPASS) &&
			ctx->state->ct_result.flags & CALI_CT_FLAG_VIA_NAT_IF) {
		CALI_DEBUG("should route via bpfnatout\n");
		ctx->fwd.mark |= CALI_SKB_MARK_TO_NAT_IFACE_OUT;
		/* bpfnatout need to process the packet */
		ct_result_set_rc(ctx->state->ct_result.rc, CALI_CT_ESTABLISHED);
	}

	if (ct_result_rpf_failed(ctx->state->ct_result.rc)) {
		if (!CALI_F_FROM_WEP) {
			/* We are possibly past (D)NAT, but that is ok, we need to let the
			 * IP stack do the RPF check on the source, dest is not important.
			 */
			goto deny;
		} else if (!wep_rpf_check(ctx, cali_rt_lookup(&ctx->state->ip_src))) {
			goto deny;
		}
	}

	if (ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_MID_FLOW_MISS) {
		if (CALI_F_TO_HOST) {
			/* Mid-flow miss: let iptables handle it in case it's an existing flow
			 * in the Linux conntrack table. We can't apply policy or DNAT because
			 * it's too late in the flow.  iptables will drop if the flow is not
			 * known.
			 */
			CALI_DEBUG("CT mid-flow miss; fall through to iptables.\n");
			ctx->fwd.mark = CALI_SKB_MARK_FALLTHROUGH;
			fwd_fib_set(&ctx->fwd, false);
			goto finalize;
		} else {
			if (CALI_F_HEP) {
				// HEP egress for a mid-flow packet with no BPF or Linux CT state.
				// This happens, for example, with asymmetric untracked policy,
				// where we want the return path packet to be dropped if there is a
				// HEP present (regardless of the policy configured on it, for
				// consistency with the iptables dataplane's invalid CT state
				// check), but allowed if there is no HEP, i.e. the egress interface
				// is a plain data interface. Unfortunately we have no simple check
				// for "is there a HEP here?" All we can do - below - is try to
				// tail call the policy program; if that attempt returns, it means
				// there is no HEP. So what we can do is set a state flag to record
				// the situation that we are in, then let the packet continue. If
				// we find that there is no policy program - i.e. no HEP - the
				// packet is correctly allowed.  If there is a policy program and it
				// denies, fine. If there is a policy program and it allows, but
				// the state flag is set, we drop the packet at the start of
				// calico_tc_skb_accepted_entrypoint.
				//
				// Also we are mid-flow and so it's important to suppress any CT
				// state creation - which normally follows when a packet is allowed
				// through - because that CT state would not be correct. Basically,
				// unless we see the SYN packet that starts a flow, we should never
				// have CT state for that flow.
				//
				// Net, we can use the same flag, CALI_ST_SUPPRESS_CT_STATE, both to
				// suppress CT state creation and to drop the packet if we find that
				// there is a HEP present.
				CALI_DEBUG("CT mid-flow miss to HEP with no Linux conntrack entry: "
						"continue but suppressing CT state creation.\n");
				ctx->state->flags |= CALI_ST_SUPPRESS_CT_STATE;
				ct_result_set_rc(ctx->state->ct_result.rc, CALI_CT_NEW);
			} else {
				CALI_DEBUG("CT mid-flow miss away from host with no Linux "
						"conntrack entry, drop.\n");
				goto deny;
			}
		}
	}

	/* Skip policy if we get conntrack hit */
	if (ct_result_rc(ctx->state->ct_result.rc) != CALI_CT_NEW) {
		if (ctx->state->ct_result.flags & CALI_CT_FLAG_SKIP_FIB) {
			ctx->state->flags |= CALI_ST_SKIP_FIB;
		}
		CALI_DEBUG("CT Hit\n");

		if (ctx->state->ip_proto == IPPROTO_TCP && ct_result_is_syn(ctx->state->ct_result.rc)) {
			CALI_DEBUG("Forcing policy on SYN\n");
			if (ct_result_rc(ctx->state->ct_result.rc) == CALI_CT_ESTABLISHED_DNAT) {
				/* Set DNAT info for policy */
				ctx->state->post_nat_ip_dst = ctx->state->ct_result.nat_ip;
				ctx->state->post_nat_dport = ctx->state->ct_result.nat_port;
			} else {
				ctx->state->post_nat_ip_dst = ctx->state->ip_dst;
				ctx->state->post_nat_dport = ctx->state->dport;
			}
			goto syn_force_policy;
		}
		goto skip_policy;
	}

	/* No conntrack entry, check if we should do NAT */
	nat_lookup_result nat_res = NAT_LOOKUP_ALLOW;

	if (CALI_F_TO_HOST || (CALI_F_FROM_HOST && !skb_seen(ctx->skb) && !ctx->nat_dest /* no sport conflict */)) {
		ctx->nat_dest = calico_nat_lookup_tc(ctx,
						     &ctx->state->ip_src, &ctx->state->ip_dst,
						     ctx->state->ip_proto, ctx->state->dport,
						     !ip_void(ctx->state->tun_ip), &nat_res);
	}

	if (nat_res == NAT_FE_LOOKUP_DROP) {
		CALI_DEBUG("Packet is from an unauthorised source: DROP\n");
		deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
		goto deny;
	}
	if (ctx->nat_dest != NULL) {
		ctx->state->post_nat_ip_dst = ctx->nat_dest->addr;
		ctx->state->post_nat_dport = ctx->nat_dest->port;
	} else if (nat_res == NAT_NO_BACKEND) {
		/* send icmp port unreachable if there is no backend for a service */
#ifdef IPVER6
		ctx->state->icmp_type = ICMPV6_DEST_UNREACH;
		ctx->state->icmp_code = ICMPV6_PORT_UNREACH;
#else
		ctx->state->icmp_type = ICMP_DEST_UNREACH;
		ctx->state->icmp_code = ICMP_PORT_UNREACH;
#endif
		ip_set_void(ctx->state->tun_ip);
		goto icmp_send_reply;
	} else {
		ctx->state->post_nat_ip_dst = ctx->state->ip_dst;
		ctx->state->post_nat_dport = ctx->state->dport;
		if (nat_res == NAT_EXCLUDE) {
			/* We want such packets to go through the host namespace. The main
			 * usecase of this is node-local-dns.
			 */
			ctx->state->flags |= CALI_ST_SKIP_FIB;
		}
	}

syn_force_policy:
	/* DNAT in state is set correctly now */

	if ((ip_void(ctx->state->tun_ip) && CALI_F_FROM_HEP) && !CALI_F_NAT_IF && !CALI_F_LO) {
		if (
#ifdef IPVER6

			ctx->state->ip_proto != IPPROTO_ICMPV6 &&
#endif
			!hep_rpf_check(ctx)) {
			goto deny;
		}
	}

	if (CALI_F_TO_WEP && !skb_seen(ctx->skb) &&
			cali_rt_flags_local_host(cali_rt_lookup_flags(&ctx->state->ip_src))) {
		/* Host to workload traffic always allowed.  We discount traffic that was
		 * seen by another program since it must have come in via another interface.
		 */
		CALI_DEBUG("Packet is from the host: ACCEPT\n");
		goto skip_policy;
	}

	if (CALI_F_FROM_WEP
#ifdef IPVER6
			&& ctx->state->ip_proto != IPPROTO_ICMPV6
#endif
		) {
		struct cali_rt *r = cali_rt_lookup(&ctx->state->ip_src);
		/* Do RPF check since it's our responsibility to police that. */
		if (!wep_rpf_check(ctx, r)) {
			goto deny;
		}

		// Check whether the workload needs outgoing NAT to this address.
		if (r->flags & CALI_RT_NAT_OUT) {
			if (!(cali_rt_lookup_flags(&ctx->state->post_nat_ip_dst) & CALI_RT_IN_POOL)) {
				CALI_DEBUG("Source is in NAT-outgoing pool "
					   "but dest is not, need to SNAT.\n");
				ctx->state->flags |= CALI_ST_NAT_OUTGOING;
			}
		}
		/* If 3rd party CNI is used and dest is outside cluster. See commit fc711b192f for details. */
		if (!(r->flags & CALI_RT_IN_POOL)) {
			CALI_DEBUG("Source %x not in IP pool\n", debug_ip(ctx->state->ip_src));
			r = cali_rt_lookup(&ctx->state->post_nat_ip_dst);
			if (!r || !(r->flags & (CALI_RT_WORKLOAD | CALI_RT_HOST))) {
				CALI_DEBUG("Outside cluster dest %x\n", debug_ip(ctx->state->post_nat_ip_dst));
				ctx->state->flags |= CALI_ST_SKIP_FIB;
			}
		}
	}

	/* [SMC] I had to add this revalidation when refactoring the conntrack code to use the context and
	 * adding possible packet pulls in the VXLAN logic.  I believe it is spurious but the verifier is
	 * not clever enough to spot that we'd have already bailed out if one of the pulls failed. */
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	ctx->state->pol_rc = CALI_POL_NO_MATCH;
	if (ctx->nat_dest) {
		ctx->state->nat_dest.addr = ctx->nat_dest->addr;
		ctx->state->nat_dest.port = ctx->nat_dest->port;
	} else {
		ip_set_void(ctx->state->nat_dest.addr);
		ctx->state->nat_dest.port = 0;
	}

	// For the case where the packet was sent from a socket on this host, get the
	// sending socket's cookie, so we can reverse a DNAT that the CTLB may have done.
	// This allows us to give the policy program the pre-DNAT destination as well as
	// the post-DNAT destination in all cases.
	__u64 cookie = bpf_get_socket_cookie(ctx->skb);
	if (cookie) {
		CALI_DEBUG("Socket cookie: %x\n", cookie);
		struct ct_nats_key ct_nkey = {
			.cookie	= cookie,
			.proto = ctx->state->ip_proto,
			.ip	= ctx->state->ip_dst,
			.port	= host_to_ctx_port(ctx->state->dport),
		};
		// If we didn't find a CTLB NAT entry then use the packet's own IP/port for the
		// pre-DNAT values that's set by tc_state_fill_from_iphdr() and
		// tc_state_fill_from_nextheader().
		struct sendrec_val *revnat = cali_ct_nats_lookup_elem(&ct_nkey);
		if (revnat) {
			CALI_DEBUG("Got cali_ct_nats entry; flow was NATted by CTLB.\n");
			ctx->state->pre_nat_ip_dst = revnat->ip;
			ctx->state->pre_nat_dport = ctx_port_to_host(revnat->port);
		}
	}

	if (!forwarding && rt_addr_is_local_host(&ctx->state->ip_src)) {
		CALI_DEBUG("Source IP is local host.\n");
		if (CALI_F_TO_HEP && is_failsafe_out(ctx->state->ip_proto, ctx->state->post_nat_dport, ctx->state->post_nat_ip_dst)) {
			CALI_DEBUG("Outbound failsafe port: %d. Skip policy.\n", ctx->state->post_nat_dport);
			counter_inc(ctx, CALI_REASON_ACCEPTED_BY_FAILSAFE);
			goto skip_policy;
		}
		ctx->state->flags |= CALI_ST_SRC_IS_HOST;
	}

	struct cali_rt *dest_rt = cali_rt_lookup(&ctx->state->post_nat_ip_dst);

	if (!dest_rt) {
		CALI_DEBUG("No route for post DNAT dest %x\n", debug_ip(ctx->state->post_nat_ip_dst));
		if (CALI_F_FROM_HEP) {
			/* Disable FIB, let the packet go through the host after it is
			 * policed. It is ingress into the system and we do not know what
			 * exactly is the packet's destination. It may be a local VM or
			 * something similar and we let the host to route it or dump it.
			 *
			 * https://github.com/projectcalico/calico/issues/6450
			 */
			ctx->state->flags |= CALI_ST_SKIP_FIB;
		}
		goto do_policy;
	}

	if (cali_rt_flags_local_host(dest_rt->flags)) {
		CALI_DEBUG("Post-NAT dest IP is local host.\n");
		if (CALI_F_FROM_HEP && is_failsafe_in(ctx->state->ip_proto, ctx->state->post_nat_dport, ctx->state->ip_src)) {
			CALI_DEBUG("Inbound failsafe port: %d. Skip policy.\n", ctx->state->post_nat_dport);
			counter_inc(ctx, CALI_REASON_ACCEPTED_BY_FAILSAFE);
			goto skip_policy;
		}
		ctx->state->flags |= CALI_ST_DEST_IS_HOST;
	}

	if (CALI_F_TO_HEP && ctx->nat_dest && !skb_seen(ctx->skb) && !(ctx->state->flags & CALI_ST_HOST_PSNAT)) {
		CALI_DEBUG("Host accesses nodeport backend %x:%d\n",
			   debug_ip(ctx->state->post_nat_ip_dst), ctx->state->post_nat_dport);
		CALI_DEBUG("Host accesses nodeport state->flags 0x%x\n", ctx->state->flags);
		if (cali_rt_flags_local_workload(dest_rt->flags)) {
			CALI_DEBUG("NP redir on HEP - skip policy\n");
			ctx->state->flags |= CALI_ST_CT_NP_LOOP;
			ctx->state->pol_rc = CALI_POL_ALLOW;
			goto skip_policy;
		} else if (cali_rt_flags_remote_workload(dest_rt->flags)) {
			if (CALI_F_LO) {
				CALI_DEBUG("NP redir remote on LO\n");
				ctx->state->flags |= CALI_ST_CT_NP_LOOP;
			} else if (CALI_F_MAIN && cali_rt_is_tunneled(dest_rt)) {
				CALI_DEBUG("NP redir remote on HEP to tunnel\n");
				ctx->state->flags |= CALI_ST_CT_NP_LOOP;
			}
			ctx->state->flags |= CALI_ST_CT_NP_REMOTE;
		}
	}

do_policy:
#ifdef IPVER6
	if (ctx->state->ip_proto == IPPROTO_ICMPV6) {
		switch (icmp_hdr(ctx)->icmp6_type) {
		case 130: /* multicast listener query */
		case 131: /* multicast listener report */
		case 132: /* multicast listener done */
		case 133: /* router solicitation */
		case 135: /* neighbor solicitation */
		case 136: /* neighbor advertisement */
			CALI_DEBUG("allow ICMPv6 type %d\n", icmp_hdr(ctx)->icmp6_type);
			/* We use iptables to allow it only to the host. */
			if (CALI_F_TO_HOST) {
				ctx->state->flags |= CALI_ST_SKIP_FIB;
			}
			goto skip_policy;
		}
	}
#endif

	CALI_DEBUG("About to jump to policy program.\n");
	CALI_JUMP_TO_POLICY(ctx);
	if (CALI_F_HEP) {
		CALI_DEBUG("HEP with no policy, allow.\n");
		goto skip_policy;
	} else {
		/* should not reach here */
		CALI_DEBUG("WEP with no policy, deny.\n");
		goto deny;
	}

icmp_send_reply:
	CALI_JUMP_TO(ctx, PROG_INDEX_ICMP);
	/* should not reach here */
	goto deny;

skip_policy:
	ctx->state->pol_rc = CALI_POL_ALLOW;
	ctx->state->flags |= CALI_ST_SKIP_POLICY;
	CALI_JUMP_TO(ctx, PROG_INDEX_ALLOWED);
	CALI_DEBUG("jump failed\n");
	/* should not reach here */
	goto deny;

finalize:
	return;

deny:
	ctx->fwd.res = TC_ACT_SHOT;
}

enum do_nat_res {
	NAT_DENY,
	NAT_ALLOW,
	NAT_ENCAP_ALLOW,
	NAT_ICMP_TOO_BIG,
};

static CALI_BPF_INLINE enum do_nat_res do_nat(struct cali_tc_ctx *ctx,
					      size_t ip_hdr_offset,
					      size_t l4_csum_off,
					      bool ct_related,
					      int ct_rc,
					      struct ct_create_ctx *ct_ctx_nat,
					      bool *is_dnat,
					      __u32 *seen_mark,
					      bool inner_icmp)
{
	bool encap_needed = false;
#ifdef IPVER6
	size_t l3_csum_off = 0;
#else
	size_t l3_csum_off = ip_hdr_offset + offsetof(struct iphdr, check);
#endif

	switch (ct_rc){
	case CALI_CT_ESTABLISHED_DNAT:
		if (CALI_F_FROM_HEP && !ip_void(STATE->tun_ip) && ct_result_np_node(STATE->ct_result)) {
			/* Packet is returning from a NAT tunnel,
			 * already SNATed, just forward it.
			 */
			*seen_mark = CALI_SKB_MARK_BYPASS_FWD;
			CALI_DEBUG("returned from NAT tunnel\n");
			goto allow;
		}
		STATE->post_nat_ip_dst = STATE->ct_result.nat_ip;
		STATE->post_nat_dport = STATE->ct_result.nat_port;

		/* fall through */

	case CALI_CT_NEW:
		/* We may not do a true DNAT here if we are resolving service source port
		 * conflict with host->pod w/o service. See calico_tc_host_ct_conflict().
		 */
		*is_dnat = !ip_equal(STATE->ip_dst, STATE->post_nat_ip_dst) || STATE->dport != STATE->post_nat_dport;

		CALI_DEBUG("CT: DNAT to %x:%d\n",
				debug_ip(STATE->post_nat_ip_dst), STATE->post_nat_dport);

		encap_needed = dnat_should_encap();

		/* We have not created the conntrack yet since we did not know
		 * if we need encap or not. Must do before MTU check and before
		 * we jump to do the encap.
		 */
		if (ct_ctx_nat /* iff CALI_CT_NEW */) {
			struct cali_rt * rt;

			if (encap_needed) {
				/* When we need to encap, we need to find out if the backend is
				 * local or not. If local, we actually do not need the encap.
				 */
				rt = cali_rt_lookup(&STATE->post_nat_ip_dst);
				if (!rt) {
					deny_reason(ctx, CALI_REASON_RT_UNKNOWN);
					goto deny;
				}
				CALI_DEBUG("rt found for 0x%x local %d\n",
						debug_ip(STATE->post_nat_ip_dst), !!cali_rt_is_local(rt));

				encap_needed = !cali_rt_is_local(rt);
				if (encap_needed) {
					if (CALI_F_FROM_HEP && ip_void(STATE->tun_ip)) {
						if (CALI_F_DSR) {
							ct_ctx_nat->flags |= CALI_CT_FLAG_DSR_FWD |
								(STATE->ct_result.flags & CALI_CT_FLAG_NP_NO_DSR);
						}
						ct_ctx_nat->flags |= CALI_CT_FLAG_NP_FWD;
					}

					ct_ctx_nat->allow_return = true;
					ct_ctx_nat->tun_ip = rt->next_hop;
					STATE->ip_dst = rt->next_hop;
				} else if (cali_rt_is_workload(rt) &&
						!ip_equal(STATE->ip_dst, STATE->post_nat_ip_dst) &&
						!CALI_F_NAT_IF) {
					/* Packet arrived from a HEP for a workload and we're
					 * about to NAT it.  We can't rely on the kernel's RPF check
					 * to do the right thing here in the presence of source
					 * based routing because the kernel would do the RPF check
					 * based on the post-NAT dest IP and that may give the wrong
					 * result.
					 *
					 * Marking the packet allows us to influence which routing
					 * rule is used.
					 */

					ct_ctx_nat->flags |= CALI_CT_FLAG_EXT_LOCAL;
					STATE->ct_result.flags |= CALI_CT_FLAG_EXT_LOCAL;
					CALI_DEBUG("CT_NEW marked with FLAG_EXT_LOCAL\n");
				}
			}

			if (CALI_F_FROM_WEP && ip_equal(STATE->ip_src, STATE->post_nat_ip_dst)) {
				CALI_DEBUG("New loopback SNAT\n");
				ct_ctx_nat->flags |= CALI_CT_FLAG_SVC_SELF;
				STATE->ct_result.flags |= CALI_CT_FLAG_SVC_SELF;
			}

			ct_ctx_nat->type = CALI_CT_TYPE_NAT_REV;
			int err;
			if ((err = conntrack_create(ctx, ct_ctx_nat))) {
				CALI_DEBUG("Creating NAT conntrack failed with %d\n", err);
				goto deny;
			}
			STATE->ct_result.nat_sip = ct_ctx_nat->src;
			STATE->ct_result.nat_sport = ct_ctx_nat->sport;
		} else {
			if (encap_needed && ct_result_np_node(STATE->ct_result)) {
				CALI_DEBUG("CT says encap to node %x\n", debug_ip(STATE->ct_result.tun_ip));
				STATE->ip_dst = STATE->ct_result.tun_ip;
			} else {
				encap_needed = false;
			}
		}
		if (encap_needed) {
			if (!(STATE->ip_proto == IPPROTO_TCP && skb_is_gso(ctx->skb)) &&
					ip_is_dnf(ip_hdr(ctx)) && vxlan_encap_too_big(ctx)) {
				CALI_DEBUG("Request packet with DNF set is too big\n");
				goto icmp_too_big;
			}
			STATE->ip_src = HOST_IP;
			*seen_mark = CALI_SKB_MARK_BYPASS_FWD; /* Do FIB if possible */
			CALI_DEBUG("marking CALI_SKB_MARK_BYPASS_FWD\n");

			goto nat_encap;
		}

		ip_hdr_set_ip(ctx, saddr, STATE->ct_result.nat_sip);
		ip_hdr_set_ip(ctx, daddr, STATE->post_nat_ip_dst);

		switch (STATE->ip_proto) {
		case IPPROTO_TCP:
			if (STATE->ct_result.nat_sport) {
				CALI_DEBUG("Fixing TCP source port from %d to %d\n",
						bpf_ntohs(tcp_hdr(ctx)->source), STATE->ct_result.nat_sport);
				tcp_hdr(ctx)->source = bpf_htons(STATE->ct_result.nat_sport);
			}
			tcp_hdr(ctx)->dest = bpf_htons(STATE->post_nat_dport);
			break;
		case IPPROTO_UDP:
			if (STATE->ct_result.nat_sport) {
				CALI_DEBUG("Fixing UDP source port from %d to %d\n",
						bpf_ntohs(udp_hdr(ctx)->source), STATE->ct_result.nat_sport);
				udp_hdr(ctx)->source = bpf_htons(STATE->ct_result.nat_sport);
			}
			udp_hdr(ctx)->dest = bpf_htons(STATE->post_nat_dport);
			break;
		}

		CALI_DEBUG("DNAT L3 csum at %d L4 csum at %d\n", l3_csum_off, l4_csum_off);

		if (l4_csum_off) {
			if (skb_nat_l4_csum(ctx, l4_csum_off,
					    STATE->ip_src,
					    STATE->ct_result.nat_sip,
					    STATE->ip_dst,
					    STATE->post_nat_ip_dst,
					    bpf_htons(STATE->dport),
					    bpf_htons(STATE->post_nat_dport),
					    bpf_htons(STATE->sport),
					    bpf_htons(STATE->ct_result.nat_sport ? : STATE->sport),
					    STATE->ip_proto == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0,
					    inner_icmp)) {
				goto deny;
			}
		}

		if (inner_icmp) {
			/* updating related icmp inner header. Because it can be anywhere
			 * and we are not updating in-place, we need to write it back
			 * before we update the csum.
			 */
			if (bpf_skb_store_bytes(ctx->skb, ip_hdr_offset, ip_hdr(ctx), IP_SIZE, 0)) {
				CALI_DEBUG("Too short for IP write back\n");
				deny_reason(ctx, CALI_REASON_SHORT);
				goto deny;
			}

			if (bpf_skb_store_bytes(ctx->skb, ip_hdr_offset + ctx->ipheader_len, ctx->nh, 8, 0)) {
				CALI_DEBUG("Too short for L4 ports write back\n");
				deny_reason(ctx, CALI_REASON_SHORT);
				goto deny;
			}
		}

#ifndef IPVER6
		if (bpf_l3_csum_replace(ctx->skb, l3_csum_off, STATE->ip_src, STATE->ct_result.nat_sip, 4) ||
				bpf_l3_csum_replace(ctx->skb, l3_csum_off, STATE->ip_dst, STATE->post_nat_ip_dst, 4)) {
			deny_reason(ctx, CALI_REASON_CSUM_FAIL);
			goto deny;
		}
#endif
		/* From now on, the packet has a new source IP */
		if (!ip_void(STATE->ct_result.nat_sip)) {
			STATE->ip_src = STATE->ct_result.nat_sip;
		}

		/* Handle returning ICMP related to tunnel
		 *
		 * N.B. we assume that we can fit in the MTU. Since it is ICMP
		 * and even though Linux sends up to min ipv4 MTU, it is
		 * unlikely that we are anywhere to close the MTU limit. If we
		 * are, we need to fail anyway.
		 */
		if (ct_related && STATE->ip_proto == IPPROTO_ICMP
				&& !ip_void(STATE->ct_result.tun_ip)
				&& (!CALI_F_DSR || (STATE->ct_result.flags & CALI_CT_FLAG_NP_NO_DSR))) {
			if (dnat_return_should_encap()) {
				CALI_DEBUG("Returning related ICMP from workload to tunnel\n");
			} else if (CALI_F_TO_HEP) {
				/* Special case for ICMP error being returned by the host with the
				 * backing workload into the tunnel back to the original host. It is
				 * ICMP related and there is a return tunnel path. We need to change
				 * both the source and destination at once.
				 *
				 * XXX the packet was routed to the original client as if it was XXX
				 * DSR and we might not be on the right iface!!! Should we XXX try
				 * to reinject it to fix the routing?
				 */
				CALI_DEBUG("Returning related ICMP from host to tunnel\n");
			}

			STATE->ip_src = HOST_IP;
			STATE->ip_dst = STATE->ct_result.tun_ip;
			goto nat_encap;
		}

		STATE->dport = STATE->post_nat_dport;
		STATE->ip_dst = STATE->post_nat_ip_dst;

		goto allow;

	case CALI_CT_ESTABLISHED_SNAT:
		CALI_DEBUG("CT: SNAT from %x:%d\n",
				debug_ip(STATE->ct_result.nat_ip), STATE->ct_result.nat_port);

		if (dnat_return_should_encap() && !ip_void(STATE->ct_result.tun_ip)) {
			if (CALI_F_DSR && !(STATE->ct_result.flags & CALI_CT_FLAG_NP_NO_DSR)) {
				/* SNAT will be done after routing, when leaving HEP */
				CALI_DEBUG("DSR enabled, skipping SNAT + encap\n");
				goto allow;
			}

			if (!(STATE->ip_proto == IPPROTO_TCP && skb_is_gso(ctx->skb)) &&
					ip_is_dnf(ip_hdr(ctx)) && vxlan_encap_too_big(ctx)) {
				CALI_DEBUG("Return ICMP mtu is too big\n");
				goto icmp_too_big;
			}
		}

		// Actually do the NAT.
		ip_hdr_set_ip(ctx, saddr, STATE->ct_result.nat_ip);
		ip_hdr_set_ip(ctx, daddr, STATE->ct_result.nat_sip);

		switch (ctx->state->ip_proto) {
		case IPPROTO_TCP:
			tcp_hdr(ctx)->source = bpf_htons(STATE->ct_result.nat_port);
			if (STATE->ct_result.nat_sport) {
				CALI_DEBUG("Fixing TCP dest port from %d to %d\n",
						bpf_ntohs(tcp_hdr(ctx)->dest), STATE->ct_result.nat_sport);
				tcp_hdr(ctx)->dest = bpf_htons(STATE->ct_result.nat_sport);
			}
			break;
		case IPPROTO_UDP:
			udp_hdr(ctx)->source = bpf_htons(STATE->ct_result.nat_port);
			if (STATE->ct_result.nat_sport) {
				CALI_DEBUG("Fixing UDP dest port from %d to %d\n",
						bpf_ntohs(tcp_hdr(ctx)->dest), STATE->ct_result.nat_sport);
				udp_hdr(ctx)->dest = bpf_htons(STATE->ct_result.nat_sport);
			}
			break;
		}

		CALI_DEBUG("SNAT L3 csum at %d L4 csum at %d\n", l3_csum_off, l4_csum_off);

		if (l4_csum_off && skb_nat_l4_csum(ctx, l4_csum_off,
						   STATE->ip_src, STATE->ct_result.nat_ip,
						   STATE->ip_dst, STATE->ct_result.nat_sip,
						   bpf_htons(STATE->dport),
						   bpf_htons(STATE->ct_result.nat_sport ? : STATE->dport),
						   bpf_htons(STATE->sport), bpf_htons(STATE->ct_result.nat_port),
						   STATE->ip_proto == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0,
						   inner_icmp)) {
			deny_reason(ctx, CALI_REASON_CSUM_FAIL);
			goto deny;
		}

		if (inner_icmp) {
			/* updating related icmp inner header. Because it can be anywhere
			 * and we are not updating in-place, we need to write it back
			 * before we update the csum.
			 */
			if (bpf_skb_store_bytes(ctx->skb, ip_hdr_offset, ip_hdr(ctx), IP_SIZE, 0)) {
				CALI_DEBUG("Too short\n");
				deny_reason(ctx, CALI_REASON_SHORT);
				goto deny;
			}

			if (bpf_skb_store_bytes(ctx->skb, ip_hdr_offset + ctx->ipheader_len, ctx->scratch->l4, 8, 0)) {
				CALI_DEBUG("Too short\n");
				deny_reason(ctx, CALI_REASON_SHORT);
				goto deny;
			}
		}

#ifndef IPVER6
		CALI_VERB("L3 checksum update (csum is at %d) port from %x to %x\n",
				l3_csum_off, STATE->ip_src, STATE->ct_result.nat_ip);

		if (bpf_l3_csum_replace(ctx->skb, l3_csum_off,
						  STATE->ip_src, STATE->ct_result.nat_ip, 4) ||
			bpf_l3_csum_replace(ctx->skb, l3_csum_off,
						  STATE->ip_dst, STATE->ct_result.nat_sip, 4)) {
			deny_reason(ctx, CALI_REASON_CSUM_FAIL);
			goto deny;
		}
#endif

		/* In addition to dnat_return_should_encap() we also need to encap on the
		 * host endpoint for egress traffic, when we hit an SNAT rule. This is the
		 * case when the target was host namespace. If the target was a pod, the
		 * already encaped traffic would not reach this point and would not be
		 * able to match as SNAT.
		 */
		if ((dnat_return_should_encap() || (CALI_F_TO_HEP && !CALI_F_DSR)) &&
									!ip_void(STATE->ct_result.tun_ip)) {
			STATE->ip_src = HOST_IP;
			STATE->ip_dst = STATE->ct_result.tun_ip;
			goto nat_encap;
		}

		STATE->sport = STATE->ct_result.nat_port;
		STATE->ip_src = STATE->ct_result.nat_ip;

		goto allow;
	}

deny:
	return NAT_DENY;

allow:
	return NAT_ALLOW;

icmp_too_big:
#ifndef IPVER6
	STATE->icmp_type = ICMP_DEST_UNREACH;
	STATE->icmp_code = ICMP_FRAG_NEEDED;

	struct {
		__be16  unused;
		__be16  mtu;
	} frag = {
		.mtu = bpf_htons(TUNNEL_MTU),
	};
	STATE->icmp_un = *(__be32 *)&frag;
#else
	STATE->icmp_type = ICMPV6_PKT_TOOBIG;
	STATE->icmp_code = 0;
	STATE->icmp_un = bpf_htonl(TUNNEL_MTU);
#endif

	return NAT_ICMP_TOO_BIG;

nat_encap:
	/* XXX */
	/* We are about to encap return traffic that originated on the local host
	 * namespace - a host networked pod. Routing was based on the dst IP,
	 * which was the original client's IP at that time, not the node's that
	 * forwarded it. We need to fix it now.
	 */
	if (CALI_F_TO_HEP) {
		struct arp_value *arpv;
		struct arp_key arpk = {
			.ip = STATE->ip_dst,
			.ifindex = ctx->skb->ifindex,
		};

		arpv = cali_arp_lookup_elem(&arpk);
		if (!arpv) {
			CALI_DEBUG("ARP lookup failed for %x dev %d at HEP\n",
					debug_ip(STATE->ip_dst), arpk.ifindex);
			/* Don't drop it yet, we might get lucky and the MAC is correct */
		} else {
			if (skb_refresh_validate_ptrs(ctx, 0)) {
				deny_reason(ctx, CALI_REASON_SHORT);
				CALI_DEBUG("Too short\n");
				goto deny;
			}
			__builtin_memcpy(&eth_hdr(ctx)->h_dest, arpv->mac_dst, ETH_ALEN);
			if (STATE->ct_result.ifindex_fwd == ctx->skb->ifindex) {
				/* No need to change src MAC, if we are at the right device */
			} else {
				/* FIXME we need to redirect to the right device */
			}
		}
	}

	if (vxlan_encap(ctx, &STATE->ip_src, &STATE->ip_dst)) {
		deny_reason(ctx, CALI_REASON_ENCAP_FAIL);
		goto  deny;
	}

	STATE->sport = STATE->dport = VXLAN_PORT;
	STATE->ip_proto = IPPROTO_UDP;

	CALI_DEBUG("vxlan return %d ifindex_fwd %d\n",
			dnat_return_should_encap(), STATE->ct_result.ifindex_fwd);

	return NAT_ENCAP_ALLOW;
}

static CALI_BPF_INLINE struct fwd post_nat(struct cali_tc_ctx *ctx,
					   enum do_nat_res nat_res,
					   bool fib,
					   __u32 seen_mark,
					   bool is_dnat)
{
	struct cali_tc_state *state = ctx->state;
	int rc = TC_ACT_UNSPEC;

	switch (nat_res) {
		case NAT_ALLOW:
			goto allow;
		case NAT_ENCAP_ALLOW:
			if (dnat_return_should_encap() && state->ct_result.ifindex_fwd != CT_INVALID_IFINDEX) {
				rc = CALI_RES_REDIR_IFINDEX;
			}

			goto encap_allow;
		default:
			goto deny;
	}

allow:
	if (state->ct_result.flags & CALI_CT_FLAG_SVC_SELF) {
		CALI_DEBUG("Loopback SNAT\n");
		seen_mark |=  CALI_SKB_MARK_MASQ;
		CALI_DEBUG("marking CALI_SKB_MARK_MASQ\n");
		fib = false; /* Disable FIB because we want to drop to iptables */
	}

	if (CALI_F_TO_HEP && !skb_seen(ctx->skb) && is_dnat) {
		struct cali_rt *r = cali_rt_lookup(&state->post_nat_ip_dst);

		if (r && cali_rt_flags_local_workload(r->flags)) {
			state->ct_result.ifindex_fwd = r->if_index;
			CALI_DEBUG("NP local WL %x:%d on HEP\n",
					debug_ip(state->post_nat_ip_dst), state->post_nat_dport);
			ctx->state->flags |= CALI_ST_CT_NP_LOOP;
			fib = true; /* Enforce FIB since we want to redirect */
		} else if (!r || cali_rt_flags_remote_workload(r->flags)) {
			/* If there is no route, treat it as a remote NP BE */
			if (CALI_F_LO || CALI_F_MAIN) {
				state->ct_result.ifindex_fwd = NATIN_IFACE  ;
				CALI_DEBUG("NP remote WL %x:%d on LO or main HEP\n",
						debug_ip(state->post_nat_ip_dst), state->post_nat_dport);
				ctx->state->flags |= CALI_ST_CT_NP_LOOP;
			}
			ctx->state->flags |= CALI_ST_CT_NP_REMOTE;
			fib = true; /* Enforce FIB since we want to redirect */
		}
	}

encap_allow:
	{
		struct fwd fwd = {
			.res = rc,
			.mark = seen_mark,
		};
		fwd_fib_set(&fwd, fib);
		return fwd;
	}

deny:
	{
		struct fwd fwd = {
			.res = TC_ACT_SHOT,
			.reason = ctx->fwd.reason,
		};
		return fwd;
	}
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

	CALI_DEBUG("Entering calico_tc_skb_accepted_entrypoint\n");

	if (!(ctx->state->flags & CALI_ST_SKIP_POLICY)) {
		counter_inc(ctx, CALI_REASON_ACCEPTED_BY_POLICY);
	}

	if (CALI_F_HEP) {
		if (!(ctx->state->flags & CALI_ST_SKIP_POLICY) && (ctx->state->flags & CALI_ST_SUPPRESS_CT_STATE)) {
			// See comment above where CALI_ST_SUPPRESS_CT_STATE is set.
			CALI_DEBUG("Egress HEP should drop packet with no CT state\n");
			return TC_ACT_SHOT;
		}
	}

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	update_rule_counters(ctx);

	ctx->fwd = calico_tc_skb_accepted(ctx);
	return forward_or_drop(ctx);

deny:
	return TC_ACT_SHOT;
}

static CALI_BPF_INLINE void update_fib_mark(struct cali_tc_state *state, bool* fib, __u32 *seen_mark)
{
	if (CALI_F_FROM_WEP && (state->flags & CALI_ST_NAT_OUTGOING)) {
		// We are going to SNAT this traffic, using iptables SNAT so set the mark
		// to trigger that and leave the fib lookup disabled.
		*fib = false;
		*seen_mark = CALI_SKB_MARK_NAT_OUT;
	} else {
		if (state->flags & CALI_ST_SKIP_FIB) {
			*fib = false;
			*seen_mark = CALI_SKB_MARK_SKIP_FIB;
		}
	}
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
	int ct_rc = ct_result_rc(state->ct_result.rc);
	__u32 seen_mark = ctx->fwd.mark;
	bool fib = true;

	CALI_DEBUG("Entering calico_tc_skb_new_flow\n");

	switch (state->pol_rc) {
	case CALI_POL_NO_MATCH:
		CALI_DEBUG("Implicitly denied by policy: DROP\n");
		goto deny;
	case CALI_POL_DENY:
		CALI_DEBUG("Denied by policy: DROP\n");
		goto deny;
	case CALI_POL_ALLOW:
		CALI_DEBUG("Allowed by policy: ACCEPT\n");
	}

	if (CALI_F_FROM_WEP &&
			CALI_DROP_WORKLOAD_TO_HOST &&
			cali_rt_flags_local_host(
				cali_rt_lookup_flags(&state->post_nat_ip_dst))) {
		CALI_DEBUG("Workload to host traffic blocked by "
			   "DefaultEndpointToHostAction: DROP\n");
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
	if (CALI_F_FROM_WEP && state->flags & CALI_ST_SKIP_FIB) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_SKIP_FIB;
	}
	/* Packets received at WEP with CALI_CT_FLAG_SKIP_FIB mark signal
	 * that all traffic on this connection must flow via host namespace as it was
	 * originally meant for host, but got redirected to a WEP by a 3rd party DNAT rule.
	 */
	if (CALI_F_TO_WEP && ((ctx->skb->mark & CALI_SKB_MARK_SKIP_FIB) == CALI_SKB_MARK_SKIP_FIB)) {
		ct_ctx_nat->flags |= CALI_CT_FLAG_SKIP_FIB;
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
		CALI_DEBUG("state->tun_ip = 0x%x\n", debug_ip(state->tun_ip));
		if (!ip_void(state->tun_ip) && cali_rt_lookup_flags(&state->ip_src) & CALI_RT_NO_DSR) {
			ct_ctx_nat->flags |= CALI_CT_FLAG_NP_NO_DSR;
			CALI_DEBUG("CALI_CT_FLAG_NP_NO_DSR\n");
		}
	}

	if (state->ip_proto == IPPROTO_TCP) {
		if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short for TCP: DROP\n");
			goto deny;
		}
		ct_ctx_nat->tcp = tcp_hdr(ctx);
	}

	// If we get here, we've passed policy.

	if (ip_void(ctx->state->nat_dest.addr)) {
		if (conntrack_create(ctx, ct_ctx_nat)) {
			CALI_DEBUG("Creating normal conntrack failed\n");

			if ((CALI_F_FROM_HEP && rt_addr_is_local_host(&ct_ctx_nat->dst)) ||
					(CALI_F_TO_HEP && rt_addr_is_local_host(&ct_ctx_nat->src))) {
				CALI_DEBUG("Allowing local host traffic without CT\n");
				goto allow;
			}

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
			CALI_DEBUG("remote wl %x tunneled via %x\n",
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
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	nat_res = do_nat(ctx, skb_iphdr_offset(ctx), l4_csum_off, false,
			 ct_rc, ct_ctx_nat, &is_dnat, &seen_mark, false);
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

static CALI_BPF_INLINE struct fwd calico_tc_skb_accepted(struct cali_tc_ctx *ctx)
{
	CALI_DEBUG("Entering calico_tc_skb_accepted\n");
	struct cali_tc_state *state = ctx->state;
	bool fib = true;
	int ct_rc = ct_result_rc(state->ct_result.rc);
	bool ct_related = ct_result_is_related(state->ct_result.rc);
	__u32 seen_mark = ctx->fwd.mark;
	size_t l4_csum_off = 0;
#ifndef IPVER6
	size_t l3_csum_off = 0;
#endif
	bool is_dnat = false;
	enum do_nat_res nat_res = NAT_ALLOW;

	CALI_DEBUG("src=%x dst=%x\n", debug_ip(state->ip_src), debug_ip(state->ip_dst));
	CALI_DEBUG("post_nat=%x:%d\n", debug_ip(state->post_nat_ip_dst), state->post_nat_dport);
	CALI_DEBUG("tun_ip=%x\n", debug_ip(state->tun_ip));
	CALI_DEBUG("pol_rc=%d\n", state->pol_rc);
	CALI_DEBUG("sport=%d\n", state->sport);
	CALI_DEBUG("dport=%d\n", state->dport);
	CALI_DEBUG("flags=%x\n", state->flags);
	CALI_DEBUG("ct_rc=%d\n", ct_rc);
	CALI_DEBUG("ct_related=%d\n", ct_related);
	CALI_DEBUG("mark=0x%x\n", seen_mark);

	ctx->fwd.reason = CALI_REASON_UNKNOWN;

	// Set the dport to 0, to make sure conntrack entries for icmp is proper as we use
	// dport to hold icmp type and code
	if (state->ip_proto == IPPROTO_ICMP_46) {
		state->dport = 0;
		state->post_nat_dport = 0;
	}

	update_fib_mark(state, &fib, &seen_mark);

	/* We check the ttl here to avoid needing complicated handling of
	 * related traffic back from the host if we let the host to handle it.
	 */
#ifdef IPVER6
	CALI_DEBUG("ip->hop_limit %d\n", ip_hdr(ctx)->hop_limit);
#else
	CALI_DEBUG("ip->ttl %d\n", ip_hdr(ctx)->ttl);
#endif
	if (ip_ttl_exceeded(ip_hdr(ctx))) {
		switch (ct_rc){
		case CALI_CT_NEW:
			if (!ip_void(ctx->state->nat_dest.addr)) {
				goto icmp_ttl_exceeded;
			}
			break;
		case CALI_CT_ESTABLISHED_DNAT:
		case CALI_CT_ESTABLISHED_SNAT:
			goto icmp_ttl_exceeded;
		}
	}

	if (ct_rc == CALI_CT_NEW) {
		CALI_JUMP_TO(ctx, PROG_INDEX_NEW_FLOW);
		/* should not reach here */
		CALI_DEBUG("jump to new flow failed\n");
		goto deny;
	}

#ifndef IPVER6
	l3_csum_off = skb_iphdr_offset(ctx) + offsetof(struct iphdr, check);
#endif

	if (ct_related) {
		if (ctx->state->ip_proto == IPPROTO_ICMP_46) {
			bool outer_ip_snat;

			/* if we do SNAT ... */
			outer_ip_snat = ct_rc == CALI_CT_ESTABLISHED_SNAT;
			/* ... there is a return path to the tunnel ... */
			outer_ip_snat = outer_ip_snat && !ip_void(state->ct_result.tun_ip);
			/* ... and should do encap and it is not DSR or it is leaving host
			 * and either DSR from WEP or originated at host ... */
			outer_ip_snat = outer_ip_snat &&
				((dnat_return_should_encap() && !CALI_F_DSR) ||
				 (CALI_F_TO_HEP &&
				  ((CALI_F_DSR && skb_seen(ctx->skb)) || !skb_seen(ctx->skb))));

			/* ... then fix the outer header IP first */
			if (outer_ip_snat) {
				ip_hdr_set_ip(ctx, saddr, state->ct_result.nat_ip);
#ifdef IPVER6
				/* ... icmp6 has checksum now, fix it! */
				l4_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct icmp6hdr, icmp6_cksum);

				__wsum csum = 0;
				csum = bpf_csum_diff((__u32*)&STATE->ip_src, sizeof(ipv6_addr_t),
						     (__u32*)&STATE->ct_result.nat_ip, sizeof(ipv6_addr_t),
						     csum);
				csum = bpf_csum_diff((__u32*)&STATE->ip_dst, sizeof(ipv6_addr_t),
						     (__u32*)&STATE->ct_result.nat_sip, sizeof(ipv6_addr_t),
						     csum);
				int res = bpf_l4_csum_replace(ctx->skb, l4_csum_off, 0, csum,  BPF_F_PSEUDO_HDR);
				if (res) {
					deny_reason(ctx, CALI_REASON_CSUM_FAIL);
					goto deny;
				}
#else
				int res = bpf_l3_csum_replace(ctx->skb, l3_csum_off,
						state->ip_src, state->ct_result.nat_ip, 4);
				if (res) {
					deny_reason(ctx, CALI_REASON_CSUM_FAIL);
					goto deny;
				}
#endif
				CALI_DEBUG("ICMP related: outer IP SNAT to %x\n",
						debug_ip(state->ct_result.nat_ip));
			}

			/* Related ICMP traffic must be an error response so it should include inner IP
			 * and 8 bytes as payload. */
			if (skb_refresh_validate_ptrs(ctx, ICMP_SIZE + sizeof(struct iphdr) + 8)) {
				deny_reason(ctx, CALI_REASON_SHORT);
				CALI_DEBUG("Failed to revalidate packet size\n");
				goto deny;
			}

			switch (ct_rc) {
			case CALI_CT_ESTABLISHED_SNAT:
			case CALI_CT_ESTABLISHED_DNAT:
				CALI_JUMP_TO(ctx, PROG_INDEX_ICMP_INNER_NAT);
				/* should not reach here */
				CALI_DEBUG("jump to icmp inner nat failed\n");
				goto deny;
			}
		}
	}

	switch (ctx->state->ip_proto) {
	case IPPROTO_TCP:
		l4_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct tcphdr, check);
		break;
	case IPPROTO_UDP:
		l4_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct udphdr, check);
		break;
	}

	switch (ct_rc){
	case CALI_CT_ESTABLISHED_DNAT:
	case CALI_CT_ESTABLISHED_SNAT:
		nat_res = do_nat(ctx, skb_iphdr_offset(ctx), l4_csum_off, false,
				 ct_rc, NULL, &is_dnat, &seen_mark, false);
		if (nat_res == NAT_ICMP_TOO_BIG) {
			goto icmp_send_reply;
		}
		goto do_post_nat;

	case CALI_CT_ESTABLISHED_BYPASS:
		if (!ct_result_is_syn(state->ct_result.rc)) {
			seen_mark = CALI_SKB_MARK_BYPASS;
			CALI_DEBUG("marking CALI_SKB_MARK_BYPASS\n");
		}
		// fall through
	case CALI_CT_ESTABLISHED:
		goto allow;
	default:
		if (CALI_F_FROM_HEP) {
			/* Since we're using the host endpoint program for TC-redirect
			 * acceleration for workloads (but we haven't fully implemented
			 * host endpoint support yet), we can get an incorrect conntrack
			 * invalid for host traffic.
			 *
			 * FIXME: Properly handle host endpoint conntrack failures
			 */
			CALI_DEBUG("Traffic is towards host namespace but not conntracked, "
				"falling through to iptables\n");
			fib = false;
			goto allow;
		}
		goto deny;
	}

	CALI_INFO("We should never fall through here\n");
	goto deny;

icmp_ttl_exceeded:
#ifdef IPVER6
	state->icmp_type = ICMPV6_TIME_EXCEED;
	state->icmp_code = ICMPV6_EXC_HOPLIMIT;
#else
	if (ip_frag_no(ip_hdr(ctx))) {
		goto deny;
	}
	state->icmp_type = ICMP_TIME_EXCEEDED;
	state->icmp_code = ICMP_EXC_TTL;
#endif
	ip_set_void(state->tun_ip);
	goto icmp_send_reply;

icmp_send_reply:
	CALI_JUMP_TO(ctx, PROG_INDEX_ICMP);
	goto deny;

allow:
do_post_nat:
	return post_nat(ctx, nat_res, fib, seen_mark, is_dnat);

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

	CALI_DEBUG("Entering calico_tc_skb_icmp_inner_nat\n");

	if (!ct_related) {
		CALI_DEBUG("ICMP: unexpected unrelated\n");
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
		CALI_DEBUG("ICMP: Drop malformed or unsupported packet\n");
		ctx->fwd.res = TC_ACT_SHOT;
		goto deny;
	}

	size_t icmp_csum_off = 0;

#ifdef IPVER6
	icmp_csum_off = skb_l4hdr_offset(ctx) + offsetof(struct icmp6hdr, icmp6_cksum);
#endif

	__u8 pkt[IP_SIZE] = { /* zero it to shut up verifier */ };
	__u8 l4pkt[8 /* what must be there */] = {};

	ctx->ip_header = (struct iphdr*)pkt;
	ctx->nh = (void *)l4pkt;

	int inner_ip_offset = skb_l4hdr_offset(ctx) + ICMP_SIZE;

	if (bpf_skb_load_bytes(ctx->skb, inner_ip_offset, pkt, IP_SIZE)) {
		CALI_DEBUG("Too short\n");
		goto deny;
	}

#ifdef IPVER6
	tc_state_fill_from_iphdr_v6_offset(ctx, inner_ip_offset);
#else
	tc_state_fill_from_iphdr_v4(ctx);
#endif

	if (bpf_skb_load_bytes(ctx->skb, inner_ip_offset + ctx->ipheader_len, l4pkt , 8)) {
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	/* Flip the direction, we need to reverse the original packet. */
	switch (ct_rc) {
		case CALI_CT_ESTABLISHED_SNAT:
			/* handle the DSR case, see CALI_CT_ESTABLISHED_SNAT where nat is done */
			if (dnat_return_should_encap() && !ip_void(state->ct_result.tun_ip)) {
				if (CALI_F_DSR) {
					/* SNAT will be done after routing, when leaving HEP */
					CALI_DEBUG("DSR enabled, skipping SNAT + encap\n");
					goto allow;
				}
			}
			ct_rc = CALI_CT_ESTABLISHED_DNAT;
			break;
		case CALI_CT_ESTABLISHED_DNAT:
			if (CALI_F_FROM_HEP && !ip_void(state->tun_ip) && ct_result_np_node(state->ct_result)) {
				/* Packet is returning from a NAT tunnel, just forward it. */
				ctx->fwd.mark = CALI_SKB_MARK_BYPASS_FWD;
				CALI_DEBUG("ICMP related returned from NAT tunnel\n");
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
		CALI_DEBUG("Non ipv4 packet on icmp path! DROP!\n");
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

	CALI_DEBUG("Entering calico_tc_skb_send_icmp_replies\n");
	CALI_DEBUG("ICMP type %d and code %d\n",ctx->state->icmp_type, ctx->state->icmp_code);

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
		CALI_DEBUG("Too short\n");
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

	CALI_DEBUG("Entering calico_tc_host_ct_conflict_entrypoint\n");

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
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
		CALI_INFO("Unexpected CT result %d after host source port collision DENY.\n",
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

	CALI_DEBUG("Entering calico_tc_skb_drop\n");

	update_rule_counters(ctx);
	counter_inc(ctx, CALI_REASON_DROPPED_BY_POLICY);

	CALI_DEBUG("proto=%d\n", ctx->state->ip_proto);
	CALI_DEBUG("src=%x dst=%x\n", debug_ip(ctx->state->ip_src),
			debug_ip(ctx->state->ip_dst));
	CALI_DEBUG("pre_nat=%x:%d\n", debug_ip(ctx->state->pre_nat_ip_dst),
			ctx->state->pre_nat_dport);
	CALI_DEBUG("post_nat=%x:%d\n", debug_ip(ctx->state->post_nat_ip_dst), ctx->state->post_nat_dport);
	CALI_DEBUG("tun_ip=%x\n", debug_ip(ctx->state->tun_ip));
	CALI_DEBUG("pol_rc=%d\n", ctx->state->pol_rc);
	CALI_DEBUG("sport=%d\n", ctx->state->sport);
	CALI_DEBUG("flags=0x%x\n", ctx->state->flags);
	CALI_DEBUG("ct_rc=%d\n", ctx->state->ct_result.rc);

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
			CALI_INFO("Allowing WG %x <-> %x despite blocked by policy - known hosts.\n",
					debug_ip(ctx->state->ip_src), debug_ip(ctx->state->ip_dst));
			goto allow;
		}
	}

	goto deny;

allow:
	ctx->state->pol_rc = CALI_POL_ALLOW;
	ctx->state->flags |= CALI_ST_SKIP_POLICY;
	CALI_JUMP_TO(ctx, PROG_INDEX_ALLOWED);
	/* should not reach here */
	CALI_DEBUG("Failed to jump to allow program.");

deny:
	CALI_DEBUG("DENY due to policy");
	return TC_ACT_SHOT;
}
