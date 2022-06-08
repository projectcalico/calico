// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>


#include "bpf.h"
#include "types.h"
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
#include "tc.h"
#include "tcv6.h"
#include "policy_program.h"
#include "parsing.h"
#include "failsafe.h"
#include "metadata.h"
#include "bpf_helpers.h"

#if !defined(__BPFTOOL_LOADER__) && !defined (__IPTOOL_LOADER__)
const volatile struct cali_tc_globals __globals;
#endif

/* calico_tc is the main function used in all of the tc programs.  It is specialised
 * for particular hook at build time based on the CALI_F build flags.
 */
static CALI_BPF_INLINE int calico_tc(struct __sk_buff *skb)
{
#ifdef UNITTEST
	/* UT-only workaround to allow us to run the program with BPF_TEST_PROG_RUN
	 * and simulate a specific mark
	 */
	skb->mark = SKB_MARK;
#endif
	CALI_DEBUG("New packet at ifindex=%d; mark=%x\n", skb->ifindex, skb->mark);

	/* Optimisation: if another BPF program has already pre-approved the packet,
	 * skip all processing. */
	if (!CALI_F_TO_HOST && skb->mark == CALI_SKB_MARK_BYPASS) {
		CALI_INFO("Final result=ALLOW (%d). Bypass mark bit set.\n", CALI_REASON_BYPASS);
		return TC_ACT_UNSPEC;
	}

	/* Optimisation: if XDP program has already accepted the packet,
	 * skip all processing. */
	if (CALI_F_FROM_HEP) {
		if (xdp2tc_get_metadata(skb) & CALI_META_ACCEPTED_BY_XDP) {
			CALI_INFO("Final result=ALLOW (%d). Accepted by XDP.\n", CALI_REASON_ACCEPTED_BY_XDP);
			skb->mark = CALI_SKB_MARK_BYPASS;
			return TC_ACT_UNSPEC;
		}
	}

	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.counters = counters_get(),
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	};
	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}
	__builtin_memset(ctx.state, 0, sizeof(*ctx.state));

	if (!ctx.counters) {
		CALI_DEBUG("Counters map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}
	INC(ctx, TOTAL_PKTS);

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx.state->prog_start_time = bpf_ktime_get_ns();
	}

	/* We only try a FIB lookup and redirect for packets that are towards the host.
	 * For packets that are leaving the host namespace, routing has already been done. */
	fwd_fib_set(&ctx.fwd, CALI_F_TO_HOST);

	if (CALI_F_TO_HEP || CALI_F_TO_WEP) {
		/* We're leaving the host namespace, check for other bypass mark bits.
		 * These are a bit more complex to handle so we do it after creating the
		 * context/state. */
		switch (skb->mark & CALI_SKB_MARK_BYPASS_MASK) {
		case CALI_SKB_MARK_BYPASS_FWD:
			CALI_DEBUG("Packet approved for forward.\n");
			ctx.fwd.reason = CALI_REASON_BYPASS;
			goto allow;
		case CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP:
			CALI_DEBUG("Packet approved for forward - src ip fixup\n");
			ctx.fwd.reason = CALI_REASON_BYPASS;

			/* we need to fix up the right src host IP */
			if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
				ctx.fwd.reason = CALI_REASON_SHORT;
				inc_counter(ctx.counters, ERR_SHORT_PKTS);
				CALI_DEBUG("Too short\n");
				goto deny;
			}

			__be32 ip_src = ctx.ip_header->saddr;
			if (ip_src == HOST_IP) {
				CALI_DEBUG("src ip fixup not needed %x\n", bpf_ntohl(ip_src));
				goto allow;
			} else {
				CALI_DEBUG("src ip fixup %x\n", bpf_ntohl(HOST_IP));
			}

			/* XXX do a proper CT lookup to find this */
			ctx.ip_header->saddr = HOST_IP;
			int l3_csum_off = skb_iphdr_offset() + offsetof(struct iphdr, check);

			int res = bpf_l3_csum_replace(skb, l3_csum_off, ip_src, HOST_IP, 4);
			if (res) {
				ctx.fwd.reason = CALI_REASON_CSUM_FAIL;
				goto deny;
			}

			goto allow;
		}
	}

	/* Parse the packet as far as the IP header; as a side-effect this validates the packet size
	 * is large enough for UDP. */
	switch (parse_packet_ip(&ctx)) {
	case PARSING_OK:
		// IPv4 Packet.
		break;
	case PARSING_OK_V6:
		// An IPv6 packet, so we should jump to the relevant IPv6 programs
		// TODO: Replace this logic with the proper implementation, and finally a
		// tail call to the IPv6 prologue program
		if (CALI_F_WEP) {
			CALI_DEBUG("IPv6 from workload: drop\n");
			goto deny;
		}
		CALI_DEBUG("IPv6 on host interface: allow\n");
		fwd_fib_set(&ctx.fwd, false);
		ctx.fwd.res = TC_ACT_UNSPEC;
		goto finalize;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		// A packet that we automatically let through
		fwd_fib_set(&ctx.fwd, false);
		ctx.fwd.res = TC_ACT_UNSPEC;
		goto finalize;
	case PARSING_ERROR:
	default:
		// A malformed packet or a packet we don't support
		CALI_DEBUG("Drop malformed or unsupported packet\n");
		ctx.fwd.res = TC_ACT_SHOT;
		goto finalize;
	}
	return pre_policy_processing(&ctx);

allow:
finalize:
	return forward_or_drop(&ctx);

deny:
	ctx.fwd.res = TC_ACT_SHOT;
	goto finalize;
}

static CALI_BPF_INLINE int pre_policy_processing(struct cali_tc_ctx *ctx)
{
	/* Now we've got as far as the UDP header, check if this is one of our VXLAN packets, which we
	 * use to forward traffic for node ports. */
	if (dnat_should_decap() /* Compile time: is this a BPF program that should decap packets? */ &&
			is_vxlan_tunnel(ctx->ip_header) /* Is this a VXLAN packet? */ ) {
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
	}

	/* Copy fields that are needed by downstream programs from the packet to the state. */
	tc_state_fill_from_iphdr(ctx);

	/* Parse out the source/dest ports (or type/code for ICMP). */
	switch (tc_state_fill_from_nexthdr(ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	ctx->state->pol_rc = CALI_POL_NO_MATCH;

	/* Do conntrack lookup before anything else */
	ctx->state->ct_result = calico_ct_v4_lookup(ctx);

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

	if (CALI_F_TO_HEP &&
			(ctx->state->ct_result.flags & CALI_CT_FLAG_VIA_NAT_IF) &&
			!(ctx->skb->mark & (CALI_SKB_MARK_FROM_NAT_IFACE_OUT | CALI_SKB_MARK_SEEN))) {
		CALI_DEBUG("Host source SNAT conflict\n");
		CALI_JUMP_TO(ctx->skb, PROG_INDEX_HOST_CT_CONFLICT);
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
		} else if (!wep_rpf_check(ctx, cali_rt_lookup(ctx->state->ip_src))) {
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

	/* Skip NAT lookup for traffic leaving the host namespace */
	if (CALI_F_TO_HOST) {
		ctx->nat_dest = calico_v4_nat_lookup2(ctx->state->ip_src, ctx->state->ip_dst,
						      ctx->state->ip_proto, ctx->state->dport,
						      ctx->state->tun_ip != 0, &nat_res);
	}

	if (nat_res == NAT_FE_LOOKUP_DROP) {
		CALI_DEBUG("Packet is from an unauthorised source: DROP\n");
		ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
		goto deny;
	}
	if (ctx->nat_dest != NULL) {
		ctx->state->post_nat_ip_dst = ctx->nat_dest->addr;
		ctx->state->post_nat_dport = ctx->nat_dest->port;
	} else if (nat_res == NAT_NO_BACKEND) {
		/* send icmp port unreachable if there is no backend for a service */
		ctx->state->icmp_type = ICMP_DEST_UNREACH;
		ctx->state->icmp_code = ICMP_PORT_UNREACH;
		ctx->state->tun_ip = 0;
		goto icmp_send_reply;
	} else {
		ctx->state->post_nat_ip_dst = ctx->state->ip_dst;
		ctx->state->post_nat_dport = ctx->state->dport;
	}

syn_force_policy:
	/* DNAT in state is set correctly now */

	if ((!(ctx->state->tun_ip) && CALI_F_FROM_HEP) && !CALI_F_NAT_IF) {
		if (!hep_rpf_check(ctx, false)) {
			goto deny;
		}
	}

	if (CALI_F_TO_WEP && !skb_seen(ctx->skb) &&
			cali_rt_flags_local_host(cali_rt_lookup_flags(ctx->state->ip_src))) {
		/* Host to workload traffic always allowed.  We discount traffic that was
		 * seen by another program since it must have come in via another interface.
		 */
		CALI_DEBUG("Packet is from the host: ACCEPT\n");
		goto skip_policy;
	}

	if (CALI_F_FROM_WEP) {
		struct cali_rt *r = cali_rt_lookup(ctx->state->ip_src);
		/* Do RPF check since it's our responsibility to police that. */
		if (!wep_rpf_check(ctx, r)) {
			goto deny;
		}

		// Check whether the workload needs outgoing NAT to this address.
		if (r->flags & CALI_RT_NAT_OUT) {
			if (!(cali_rt_lookup_flags(ctx->state->post_nat_ip_dst) & CALI_RT_IN_POOL)) {
				CALI_DEBUG("Source is in NAT-outgoing pool "
					   "but dest is not, need to SNAT.\n");
				ctx->state->flags |= CALI_ST_NAT_OUTGOING;
			}
		}
		/* If 3rd party CNI is used and dest is outside cluster. See commit fc711b192f for details. */
		if (!(r->flags & CALI_RT_IN_POOL)) {
			CALI_DEBUG("Source %x not in IP pool\n", bpf_ntohl(ctx->state->ip_src));
			r = cali_rt_lookup(ctx->state->post_nat_ip_dst);
			if (!r || !(r->flags & (CALI_RT_WORKLOAD | CALI_RT_HOST))) {
				CALI_DEBUG("Outside cluster dest %x\n", bpf_ntohl(ctx->state->post_nat_ip_dst));
				ctx->state->flags |= CALI_ST_SKIP_FIB;
			}
		}
	}

	/* [SMC] I had to add this revalidation when refactoring the conntrack code to use the context and
	 * adding possible packet pulls in the VXLAN logic.  I believe it is spurious but the verifier is
	 * not clever enough to spot that we'd have already bailed out if one of the pulls failed. */
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	ctx->state->pol_rc = CALI_POL_NO_MATCH;
	if (ctx->nat_dest) {
		ctx->state->nat_dest.addr = ctx->nat_dest->addr;
		ctx->state->nat_dest.port = ctx->nat_dest->port;
	} else {
		ctx->state->nat_dest.addr = 0;
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
		struct sendrecv4_val *revnat = cali_v4_ct_nats_lookup_elem(&ct_nkey);
		if (revnat) {
			CALI_DEBUG("Got cali_v4_ct_nats entry; flow was NATted by CTLB.\n");
			ctx->state->pre_nat_ip_dst = revnat->ip;
			ctx->state->pre_nat_dport = ctx_port_to_host(revnat->port);
		}
	}

	if (rt_addr_is_local_host(ctx->state->post_nat_ip_dst)) {
		CALI_DEBUG("Post-NAT dest IP is local host.\n");
		if (CALI_F_FROM_HEP && is_failsafe_in(ctx->state->ip_proto, ctx->state->post_nat_dport, ctx->state->ip_src)) {
			CALI_DEBUG("Inbound failsafe port: %d. Skip policy.\n", ctx->state->post_nat_dport);
			goto skip_policy;
		}
		ctx->state->flags |= CALI_ST_DEST_IS_HOST;
	}
	if (rt_addr_is_local_host(ctx->state->ip_src)) {
		CALI_DEBUG("Source IP is local host.\n");
		if (CALI_F_TO_HEP && is_failsafe_out(ctx->state->ip_proto, ctx->state->post_nat_dport, ctx->state->post_nat_ip_dst)) {
			CALI_DEBUG("Outbound failsafe port: %d. Skip policy.\n", ctx->state->post_nat_dport);
			goto skip_policy;
		}
		ctx->state->flags |= CALI_ST_SRC_IS_HOST;
	}

	CALI_DEBUG("About to jump to policy program.\n");
	CALI_JUMP_TO(ctx->skb, PROG_INDEX_POLICY);
	if (CALI_F_HEP) {
		CALI_DEBUG("HEP with no policy, allow.\n");
		goto skip_policy;
	} else {
		/* should not reach here */
		CALI_DEBUG("WEP with no policy, deny.\n");
		goto deny;
	}

icmp_send_reply:
	CALI_JUMP_TO(ctx->skb, PROG_INDEX_ICMP);
	/* should not reach here */
	goto deny;

skip_policy:
	ctx->state->pol_rc = CALI_POL_ALLOW;
	ctx->state->flags |= CALI_ST_SKIP_POLICY;
	CALI_JUMP_TO(ctx->skb, PROG_INDEX_ALLOWED);
	/* should not reach here */
	goto deny;

finalize:
	return;

deny:
	ctx->fwd.res = TC_ACT_SHOT;
}

SEC("classifier/tc/accept")
int calico_tc_skb_accepted_entrypoint(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering calico_tc_skb_accepted_entrypoint\n");
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
			.mark = CALI_SKB_MARK_SEEN,
		},
	};
	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}
	if (CALI_F_HEP) {
		if (!(ctx.state->flags & CALI_ST_SKIP_POLICY) && (ctx.state->flags & CALI_ST_SUPPRESS_CT_STATE)) {
			// See comment above where CALI_ST_SUPPRESS_CT_STATE is set.
			CALI_DEBUG("Egress HEP should drop packet with no CT state\n");
			return TC_ACT_SHOT;
		}
	}

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		ctx.fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	struct calico_nat_dest *nat_dest = NULL;
	struct calico_nat_dest nat_dest_2 = {
		.addr=ctx.state->nat_dest.addr,
		.port=ctx.state->nat_dest.port,
	};
	if (ctx.state->nat_dest.addr != 0) {
		nat_dest = &nat_dest_2;
	}

	ctx.fwd = calico_tc_skb_accepted(&ctx, nat_dest);
	return forward_or_drop(&ctx);

deny:
	return TC_ACT_SHOT;
}

static CALI_BPF_INLINE struct fwd calico_tc_skb_accepted(struct cali_tc_ctx *ctx,
							 struct calico_nat_dest *nat_dest)
{
	CALI_DEBUG("Entering calico_tc_skb_accepted\n");
	struct __sk_buff *skb = ctx->skb;
	struct cali_tc_state *state = ctx->state;

	enum calico_reason reason = CALI_REASON_UNKNOWN;
	int rc = TC_ACT_UNSPEC;
	bool fib = true;
	struct ct_create_ctx ct_ctx_nat = {};
	int ct_rc = ct_result_rc(state->ct_result.rc);
	bool ct_related = ct_result_is_related(state->ct_result.rc);
	__u32 seen_mark = ctx->fwd.mark;
	size_t l4_csum_off = 0, l3_csum_off;

	CALI_DEBUG("src=%x dst=%x\n", bpf_ntohl(state->ip_src), bpf_ntohl(state->ip_dst));
	CALI_DEBUG("post_nat=%x:%d\n", bpf_ntohl(state->post_nat_ip_dst), state->post_nat_dport);
	CALI_DEBUG("tun_ip=%x\n", state->tun_ip);
	CALI_DEBUG("pol_rc=%d\n", state->pol_rc);
	CALI_DEBUG("sport=%d\n", state->sport);
	CALI_DEBUG("flags=%x\n", state->flags);
	CALI_DEBUG("ct_rc=%d\n", ct_rc);
	CALI_DEBUG("ct_related=%d\n", ct_related);
	CALI_DEBUG("mark=0x%x\n", seen_mark);

	// Set the dport to 0, to make sure conntrack entries for icmp is proper as we use
	// dport to hold icmp type and code
	if (state->ip_proto == IPPROTO_ICMP) {
		state->dport = 0;
		state->post_nat_dport = 0;
	}

	if (CALI_F_FROM_WEP && (state->flags & CALI_ST_NAT_OUTGOING)) {
		// We are going to SNAT this traffic, using iptables SNAT so set the mark
		// to trigger that and leave the fib lookup disabled.
		fib = false;
		seen_mark = CALI_SKB_MARK_NAT_OUT;
		CALI_DEBUG("marking CALI_SKB_MARK_NAT_OUT\n");
	} else {
		if (state->flags & CALI_ST_SKIP_FIB) {
			fib = false;
			seen_mark = CALI_SKB_MARK_SKIP_FIB;
		}
	}

	/* We check the ttl here to avoid needing complicated handling of
	 * related traffic back from the host if we let the host to handle it.
	 */
	CALI_DEBUG("ip->ttl %d\n", ctx->ip_header->ttl);
	if (ip_ttl_exceeded(ctx->ip_header)) {
		switch (ct_rc){
		case CALI_CT_NEW:
			if (nat_dest) {
				goto icmp_ttl_exceeded;
			}
			break;
		case CALI_CT_ESTABLISHED_DNAT:
		case CALI_CT_ESTABLISHED_SNAT:
			goto icmp_ttl_exceeded;
		}
	}

	l3_csum_off = skb_iphdr_offset() +  offsetof(struct iphdr, check);

	if (ct_related) {
		if (ctx->ip_header->protocol == IPPROTO_ICMP) {
			bool outer_ip_snat;

			/* if we do SNAT ... */
			outer_ip_snat = ct_rc == CALI_CT_ESTABLISHED_SNAT;
			/* ... there is a return path to the tunnel ... */
			outer_ip_snat = outer_ip_snat && state->ct_result.tun_ip;
			/* ... and should do encap and it is not DSR or it is leaving host
			 * and either DSR from WEP or originated at host ... */
			outer_ip_snat = outer_ip_snat &&
				((dnat_return_should_encap() && !CALI_F_DSR) ||
				 (CALI_F_TO_HEP &&
				  ((CALI_F_DSR && skb_seen(skb)) || !skb_seen(skb))));

			/* ... then fix the outer header IP first */
			if (outer_ip_snat) {
				ctx->ip_header->saddr = state->ct_result.nat_ip;
				int res = bpf_l3_csum_replace(skb, l3_csum_off,
						state->ip_src, state->ct_result.nat_ip, 4);
				if (res) {
					reason = CALI_REASON_CSUM_FAIL;
					goto deny;
				}
				CALI_DEBUG("ICMP related: outer IP SNAT to %x\n",
						bpf_ntohl(state->ct_result.nat_ip));
			}

			/* Related ICMP traffic must be an error response so it should include inner IP
			 * and 8 bytes as payload. */
			if (skb_refresh_validate_ptrs(ctx, ICMP_SIZE + sizeof(struct iphdr) + 8)) {
				CALI_DEBUG("Failed to revalidate packet size\n");
				goto deny;
			}

			/* Skip past the ICMP header and check the inner IP header.
			 * WARNING: this modifies the ip_header pointer in the main context; need to
			 * be careful in later code to avoid overwriting that. */
			l3_csum_off += sizeof(*ctx->ip_header) + sizeof(struct icmphdr);
			ctx->ip_header = (struct iphdr *)(tc_icmphdr(ctx) + 1); /* skip to inner ip */
			if (ctx->ip_header->ihl != 5) {
				CALI_INFO("ICMP inner IP header has options; unsupported\n");
				ctx->fwd.reason = CALI_REASON_IP_OPTIONS;
				ctx->fwd.res = TC_ACT_SHOT;
				goto deny;
			}
			ctx->nh = (void*)(ctx->ip_header+1);

			/* Flip the direction, we need to reverse the original packet. */
			switch (ct_rc) {
			case CALI_CT_ESTABLISHED_SNAT:
				/* handle the DSR case, see CALI_CT_ESTABLISHED_SNAT where nat is done */
				if (dnat_return_should_encap() && state->ct_result.tun_ip) {
					if (CALI_F_DSR) {
						/* SNAT will be done after routing, when leaving HEP */
						CALI_DEBUG("DSR enabled, skipping SNAT + encap\n");
						goto allow;
					}
				}
				ct_rc = CALI_CT_ESTABLISHED_DNAT;
				break;
			case CALI_CT_ESTABLISHED_DNAT:
				if (CALI_F_FROM_HEP && state->tun_ip && ct_result_np_node(state->ct_result)) {
					/* Packet is returning from a NAT tunnel, just forward it. */
					seen_mark = CALI_SKB_MARK_BYPASS_FWD;
					CALI_DEBUG("ICMP related returned from NAT tunnel\n");
					goto allow;
				}
				ct_rc = CALI_CT_ESTABLISHED_SNAT;
				break;
			}
		}
	}

	__u8 ihl = ctx->ip_header->ihl * 4;

	int res = 0;
	bool encap_needed = false;

	if (state->ip_proto == IPPROTO_ICMP && ct_related) {
		/* do not fix up embedded L4 checksum for related ICMP */
	} else {
		switch (ctx->ip_header->protocol) {
		case IPPROTO_TCP:
			l4_csum_off = skb_l4hdr_offset(skb, ihl) + offsetof(struct tcphdr, check);
			break;
		case IPPROTO_UDP:
			l4_csum_off = skb_l4hdr_offset(skb, ihl) + offsetof(struct udphdr, check);
			break;
		}
	}

	switch (ct_rc){
	case CALI_CT_NEW:
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
					cali_rt_lookup_flags(state->post_nat_ip_dst))) {
			CALI_DEBUG("Workload to host traffic blocked by "
				   "DefaultEndpointToHostAction: DROP\n");
			goto deny;
		}

		ct_ctx_nat.skb = skb;
		ct_ctx_nat.proto = state->ip_proto;
		ct_ctx_nat.src = state->ip_src;
		ct_ctx_nat.sport = state->sport;
		ct_ctx_nat.dst = state->post_nat_ip_dst;
		ct_ctx_nat.dport = state->post_nat_dport;
		ct_ctx_nat.tun_ip = state->tun_ip;
		ct_ctx_nat.type = CALI_CT_TYPE_NORMAL;
		ct_ctx_nat.allow_return = false;
		if (state->flags & CALI_ST_NAT_OUTGOING) {
			ct_ctx_nat.flags |= CALI_CT_FLAG_NAT_OUT;
		}
		if (CALI_F_FROM_WEP && state->flags & CALI_ST_SKIP_FIB) {
			ct_ctx_nat.flags |= CALI_CT_FLAG_SKIP_FIB;
		}
		if (CALI_F_TO_HOST && CALI_F_NAT_IF) {
			ct_ctx_nat.flags |= CALI_CT_FLAG_VIA_NAT_IF;
		}
		if (state->flags & CALI_ST_HOST_PSNAT) {
			ct_ctx_nat.flags |= CALI_CT_FLAG_HOST_PSNAT;
		}
		/* Mark connections that were routed via bpfnatout, but had CT miss at
		 * HEP. That is because of SNAT happened between bpfnatout and here.
		 * Returning packets on such a connection must go back via natbpfout
		 * without a short-circuit to reverse the service NAT.
		 */
		if (CALI_F_TO_HEP &&
				((skb->mark & CALI_SKB_MARK_FROM_NAT_IFACE_OUT) == CALI_SKB_MARK_FROM_NAT_IFACE_OUT)) {
			ct_ctx_nat.flags |= CALI_CT_FLAG_VIA_NAT_IF;
		}

		if (state->ip_proto == IPPROTO_TCP) {
			if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
				CALI_DEBUG("Too short for TCP: DROP\n");
				goto deny;
			}
			ct_ctx_nat.tcp = tc_tcphdr(ctx);
		}

		// If we get here, we've passed policy.

		if (nat_dest == NULL) {
			if (conntrack_create(ctx, &ct_ctx_nat)) {
				CALI_DEBUG("Creating normal conntrack failed\n");

				if ((CALI_F_FROM_HEP && rt_addr_is_local_host(ct_ctx_nat.dst)) ||
						(CALI_F_TO_HEP && rt_addr_is_local_host(ct_ctx_nat.src))) {
					CALI_DEBUG("Allowing local host traffic without CT\n");
					goto allow;
				}

				goto deny;
			}
			goto allow;
		}

		ct_ctx_nat.orig_src = state->ip_src;
		ct_ctx_nat.orig_dst = state->ip_dst;
		ct_ctx_nat.orig_dport = state->dport;
		ct_ctx_nat.orig_sport = state->sport;
		state->ct_result.nat_sport = ct_ctx_nat.sport;
		/* fall through as DNAT is now established */

		if (CALI_F_TO_HOST && CALI_F_NAT_IF) {
			struct cali_rt *r = cali_rt_lookup(state->post_nat_ip_dst);
			if (r && cali_rt_flags_remote_workload(r->flags) && r->flags & CALI_RT_TUNNELED) {
				CALI_DEBUG("remote wl %x tunneled\n", bpf_htonl(state->post_nat_ip_dst));
				ct_ctx_nat.src = HOST_TUNNEL_IP;
				/* This would be the place to set a new source port if we
				 * had a way how to allocate it. Instead we rely on source
				 * port collision resolution.
				 * ct_ctx_nat.sport = 10101;
				 */
				state->ct_result.nat_sip = ct_ctx_nat.src;
				state->ct_result.nat_sport = ct_ctx_nat.sport;
			}
		}

	case CALI_CT_ESTABLISHED_DNAT:
		/* align with CALI_CT_NEW */
		if (ct_rc == CALI_CT_ESTABLISHED_DNAT) {
			if (CALI_F_FROM_HEP && state->tun_ip && ct_result_np_node(state->ct_result)) {
				/* Packet is returning from a NAT tunnel,
				 * already SNATed, just forward it.
				 */
				seen_mark = CALI_SKB_MARK_BYPASS_FWD;
				CALI_DEBUG("returned from NAT tunnel\n");
				goto allow;
			}
			state->post_nat_ip_dst = state->ct_result.nat_ip;
			state->post_nat_dport = state->ct_result.nat_port;
		}

		CALI_DEBUG("CT: DNAT to %x:%d\n",
				bpf_ntohl(state->post_nat_ip_dst), state->post_nat_dport);

		encap_needed = dnat_should_encap();

		/* We have not created the conntrack yet since we did not know
		 * if we need encap or not. Must do before MTU check and before
		 * we jump to do the encap.
		 */
		if (ct_rc == CALI_CT_NEW) {
			struct cali_rt * rt;

			if (encap_needed) {
				/* When we need to encap, we need to find out if the backend is
				 * local or not. If local, we actually do not need the encap.
				 */
				rt = cali_rt_lookup(state->post_nat_ip_dst);
				if (!rt) {
					reason = CALI_REASON_RT_UNKNOWN;
					goto deny;
				}
				CALI_DEBUG("rt found for 0x%x local %d\n",
						bpf_ntohl(state->post_nat_ip_dst), !!cali_rt_is_local(rt));

				encap_needed = !cali_rt_is_local(rt);
				if (encap_needed) {
					if (CALI_F_FROM_HEP && state->tun_ip == 0) {
						if (CALI_F_DSR) {
							ct_ctx_nat.flags |= CALI_CT_FLAG_DSR_FWD;
						}
						ct_ctx_nat.flags |= CALI_CT_FLAG_NP_FWD;
					}

					ct_ctx_nat.allow_return = true;
					ct_ctx_nat.tun_ip = rt->next_hop;
					state->ip_dst = rt->next_hop;
				} else if (cali_rt_is_workload(rt) &&
						state->ip_dst != state->post_nat_ip_dst &&
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

					ct_ctx_nat.flags |= CALI_CT_FLAG_EXT_LOCAL;
					ctx->state->ct_result.flags |= CALI_CT_FLAG_EXT_LOCAL;
					CALI_DEBUG("CT_NEW marked with FLAG_EXT_LOCAL\n");
				}
			}

			ct_ctx_nat.type = CALI_CT_TYPE_NAT_REV;
			int err;
			if ((err = conntrack_create(ctx, &ct_ctx_nat))) {
				CALI_DEBUG("Creating NAT conntrack failed with %d\n", err);
				goto deny;
			}
			state->ct_result.nat_sip = ct_ctx_nat.src;
			state->ct_result.nat_sport = ct_ctx_nat.sport;
		} else {
			if (encap_needed && ct_result_np_node(state->ct_result)) {
				CALI_DEBUG("CT says encap to node %x\n", bpf_ntohl(state->ct_result.tun_ip));
				state->ip_dst = state->ct_result.tun_ip;
			} else {
				encap_needed = false;
			}
		}
		if (encap_needed) {
			if (!(state->ip_proto == IPPROTO_TCP && skb_is_gso(skb)) &&
					ip_is_dnf(ctx->ip_header) && vxlan_v4_encap_too_big(ctx)) {
				CALI_DEBUG("Request packet with DNF set is too big\n");
				goto icmp_too_big;
			}
			state->ip_src = HOST_IP;
			seen_mark = CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP; /* Do FIB if possible */
			CALI_DEBUG("marking CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP\n");

			goto nat_encap;
		}

		ctx->ip_header->saddr = state->ct_result.nat_sip;
		ctx->ip_header->daddr = state->post_nat_ip_dst;

		switch (ctx->ip_header->protocol) {
		case IPPROTO_TCP:
			if (state->ct_result.nat_sport) {
				CALI_DEBUG("Fixing TCP source port from %d to %d\n",
						bpf_ntohs(tc_tcphdr(ctx)->source), state->ct_result.nat_sport);
				tc_tcphdr(ctx)->source = bpf_htons(state->ct_result.nat_sport);
			}
			tc_tcphdr(ctx)->dest = bpf_htons(state->post_nat_dport);
			break;
		case IPPROTO_UDP:
			if (state->ct_result.nat_sport) {
				CALI_DEBUG("Fixing UDP source port from %d to %d\n",
						bpf_ntohs(tc_udphdr(ctx)->source), state->ct_result.nat_sport);
				tc_udphdr(ctx)->source = bpf_htons(state->ct_result.nat_sport);
			}
			tc_udphdr(ctx)->dest = bpf_htons(state->post_nat_dport);
			break;
		}

		CALI_VERB("L3 csum at %d L4 csum at %d\n", l3_csum_off, l4_csum_off);

		if (l4_csum_off) {
			res = skb_nat_l4_csum_ipv4(skb, l4_csum_off,
					state->ip_src,
					state->ct_result.nat_sip,
					state->ip_dst,
					state->post_nat_ip_dst,
					bpf_htons(state->dport),
					bpf_htons(state->post_nat_dport),
					bpf_htons(state->sport),
					bpf_htons(state->ct_result.nat_sport ? : state->sport),
					ctx->ip_header->protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);
		}

		res |= bpf_l3_csum_replace(skb, l3_csum_off, state->ip_src, state->ct_result.nat_sip, 4);
		res |= bpf_l3_csum_replace(skb, l3_csum_off, state->ip_dst, state->post_nat_ip_dst, 4);
		/* From now on, the packet has a new source IP */
		if (state->ct_result.nat_sip) {
			state->ip_src = state->ct_result.nat_sip;
		}


		if (res) {
			reason = CALI_REASON_CSUM_FAIL;
			goto deny;
		}

		/* Handle returning ICMP related to tunnel
		 *
		 * N.B. we assume that we can fit in the MTU. Since it is ICMP
		 * and even though Linux sends up to min ipv4 MTU, it is
		 * unlikely that we are anywhere to close the MTU limit. If we
		 * are, we need to fail anyway.
		 */
		if (ct_related && state->ip_proto == IPPROTO_ICMP
				&& state->ct_result.tun_ip
				&& !CALI_F_DSR) {
			if (dnat_return_should_encap()) {
				CALI_DEBUG("Returning related ICMP from workload to tunnel\n");
				state->ip_dst = state->ct_result.tun_ip;
				seen_mark = CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP;
				goto nat_encap;
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
				state->ip_src = HOST_IP;
				state->ip_dst = state->ct_result.tun_ip;
				goto nat_encap;
			}
		}

		state->dport = state->post_nat_dport;
		state->ip_dst = state->post_nat_ip_dst;

		goto allow;

	case CALI_CT_ESTABLISHED_SNAT:
		CALI_DEBUG("CT: SNAT from %x:%d\n",
				bpf_ntohl(state->ct_result.nat_ip), state->ct_result.nat_port);

		if (dnat_return_should_encap() && state->ct_result.tun_ip) {
			if (CALI_F_DSR) {
				/* SNAT will be done after routing, when leaving HEP */
				CALI_DEBUG("DSR enabled, skipping SNAT + encap\n");
				goto allow;
			}

			if (!(state->ip_proto == IPPROTO_TCP && skb_is_gso(skb)) &&
					ip_is_dnf(ctx->ip_header) && vxlan_v4_encap_too_big(ctx)) {
				CALI_DEBUG("Return ICMP mtu is too big\n");
				goto icmp_too_big;
			}
		}

		// Actually do the NAT.
		ctx->ip_header->saddr = state->ct_result.nat_ip;
		ctx->ip_header->daddr = state->ct_result.nat_sip;

		switch (ctx->ip_header->protocol) {
		case IPPROTO_TCP:
			tc_tcphdr(ctx)->source = bpf_htons(state->ct_result.nat_port);
			if (state->ct_result.nat_sport) {
				CALI_DEBUG("Fixing TCP dest port from %d to %d\n",
						bpf_ntohs(tc_tcphdr(ctx)->dest), state->ct_result.nat_sport);
				tc_tcphdr(ctx)->dest = bpf_htons(state->ct_result.nat_sport);
			}
			break;
		case IPPROTO_UDP:
			tc_udphdr(ctx)->source = bpf_htons(state->ct_result.nat_port);
			if (state->ct_result.nat_sport) {
				CALI_DEBUG("Fixing UDP dest port from %d to %d\n",
						bpf_ntohs(tc_tcphdr(ctx)->dest), state->ct_result.nat_sport);
				tc_udphdr(ctx)->dest = bpf_htons(state->ct_result.nat_sport);
			}
			break;
		}

		CALI_VERB("L3 csum at %d L4 csum at %d\n", l3_csum_off, l4_csum_off);

		if (l4_csum_off) {
			res = skb_nat_l4_csum_ipv4(skb, l4_csum_off,
				state->ip_src, state->ct_result.nat_ip,
				state->ip_dst, state->ct_result.nat_sip,
				bpf_htons(state->dport), bpf_htons(state->ct_result.nat_sport ? : state->dport),
				bpf_htons(state->sport), bpf_htons(state->ct_result.nat_port),
				ctx->ip_header->protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);
		}

		CALI_VERB("L3 checksum update (csum is at %d) port from %x to %x\n",
				l3_csum_off, state->ip_src, state->ct_result.nat_ip);

		int csum_rc = bpf_l3_csum_replace(skb, l3_csum_off,
						  state->ip_src, state->ct_result.nat_ip, 4);
		csum_rc |= bpf_l3_csum_replace(skb, l3_csum_off,
						  state->ip_dst, state->ct_result.nat_sip, 4);
		CALI_VERB("bpf_l3_csum_replace(IP): %d\n", csum_rc);
		res |= csum_rc;

		if (res) {
			reason = CALI_REASON_CSUM_FAIL;
			goto deny;
		}

		/* In addition to dnat_return_should_encap() we also need to encap on the
		 * host endpoint for egress traffic, when we hit an SNAT rule. This is the
		 * case when the target was host namespace. If the target was a pod, the
		 * already encaped traffic would not reach this point and would not be
		 * able to match as SNAT.
		 */
		if ((dnat_return_should_encap() || (CALI_F_TO_HEP && !CALI_F_DSR)) &&
									state->ct_result.tun_ip) {
			state->ip_dst = state->ct_result.tun_ip;
			seen_mark = CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP;
			CALI_DEBUG("marking CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP\n");
			goto nat_encap;
		}

		state->sport = state->ct_result.nat_port;
		state->ip_src = state->ct_result.nat_ip;

		goto allow;

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
	if (ip_frag_no(ctx->ip_header)) {
		goto deny;
	}
	state->icmp_type = ICMP_TIME_EXCEEDED;
	state->icmp_code = ICMP_EXC_TTL;
	state->tun_ip = 0;
	goto icmp_send_reply;

icmp_too_big:
	state->icmp_type = ICMP_DEST_UNREACH;
	state->icmp_code = ICMP_FRAG_NEEDED;

	struct {
		__be16  unused;
		__be16  mtu;
	} frag = {
		.mtu = bpf_htons(TUNNEL_MTU),
	};
	state->tun_ip = *(__be32 *)&frag;

	goto icmp_send_reply;

icmp_send_reply:
	CALI_JUMP_TO(skb, PROG_INDEX_ICMP);
	goto deny;

nat_encap:
	/* We are about to encap return traffic that originated on the local host
	 * namespace - a host networked pod. Routing was based on the dst IP,
	 * which was the original client's IP at that time, not the node's that
	 * forwarded it. We need to fix it now.
	 */
	if (CALI_F_TO_HEP) {
		struct arp_value *arpv;
		struct arp_key arpk = {
			.ip = state->ip_dst,
			.ifindex = skb->ifindex,
		};

		arpv = cali_v4_arp_lookup_elem(&arpk);
		if (!arpv) {
			CALI_DEBUG("ARP lookup failed for %x dev %d at HEP\n",
					bpf_ntohl(state->ip_dst), arpk.ifindex);
			/* Don't drop it yet, we might get lucky and the MAC is correct */
		} else {
			if (skb_refresh_validate_ptrs(ctx, 0)) {
				reason = CALI_REASON_SHORT;
				goto deny;
			}
			__builtin_memcpy(&tc_ethhdr(ctx)->h_dest, arpv->mac_dst, ETH_ALEN);
			if (state->ct_result.ifindex_fwd == skb->ifindex) {
				/* No need to change src MAC, if we are at the right device */
			} else {
				/* FIXME we need to redirect to the right device */
			}
		}
	}

	if (vxlan_v4_encap(ctx, state->ip_src, state->ip_dst)) {
		reason = CALI_REASON_ENCAP_FAIL;
		goto  deny;
	}

	state->sport = state->dport = VXLAN_PORT;
	state->ip_proto = IPPROTO_UDP;

	CALI_DEBUG("vxlan return %d ifindex_fwd %d\n",
			dnat_return_should_encap(), state->ct_result.ifindex_fwd);

	if (dnat_return_should_encap() && state->ct_result.ifindex_fwd != CT_INVALID_IFINDEX) {
		rc = CALI_RES_REDIR_IFINDEX;
	}

allow:
	if (CALI_F_FROM_WEP && state->ip_src == state->ip_dst) {
		CALI_DEBUG("Loopback SNAT\n");
		seen_mark |=  CALI_SKB_MARK_MASQ;
		CALI_DEBUG("marking CALI_SKB_MARK_MASQ\n");
		fib = false; /* Disable FIB because we want to drop to iptables */
	}

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
			.reason = reason,
		};
		return fwd;
	}
}

SEC("classifier/tc/icmp")
int calico_tc_skb_send_icmp_replies(struct __sk_buff *skb)
{
	__u32 fib_flags = 0;

	CALI_DEBUG("Entering calico_tc_skb_send_icmp_replies\n");

	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	};
	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}

	CALI_DEBUG("ICMP type %d and code %d\n",ctx.state->icmp_type, ctx.state->icmp_code);

	if (ctx.state->icmp_code == ICMP_FRAG_NEEDED) {
		fib_flags |= BPF_FIB_LOOKUP_OUTPUT;
		if (CALI_F_FROM_WEP) {
			/* we know it came from workload, just send it back the same way */
			ctx.fwd.res = CALI_RES_REDIR_BACK;
		}
	}

	if (icmp_v4_reply(&ctx, ctx.state->icmp_type, ctx.state->icmp_code, ctx.state->tun_ip)) {
		ctx.fwd.res = TC_ACT_SHOT;
	} else {
		ctx.fwd.mark = CALI_SKB_MARK_BYPASS_FWD;

		fwd_fib_set(&ctx.fwd, false);
		fwd_fib_set_flags(&ctx.fwd, fib_flags);
	}

	if (skb_refresh_validate_ptrs(&ctx, ICMP_SIZE)) {
		ctx.fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	tc_state_fill_from_iphdr(&ctx);
	ctx.state->sport = ctx.state->dport = 0;
	return forward_or_drop(&ctx);
deny:
	return TC_ACT_SHOT;
}

SEC("classifier/tc/host_ct_conflict")
int calico_tc_host_ct_conflict(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering calico_tc_host_ct_conflict_entrypoint\n");
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.skb = skb,
		.fwd = {
			.res = TC_ACT_UNSPEC,
			.reason = CALI_REASON_UNKNOWN,
		},
	};

	struct calico_nat_dest nat_dest_ident;

	if (!ctx.state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		goto deny;
	}

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		ctx.fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	__u16 sport = ctx.state->sport;
	ctx.state->sport = 0;
	ctx.state->ct_result = calico_ct_v4_lookup(&ctx);
	ctx.state->sport = sport;
	ctx.state->flags |= CALI_ST_HOST_PSNAT;

	switch (ct_result_rc(ctx.state->ct_result.rc)) {
	case CALI_CT_ESTABLISHED:
		/* Because we are on the "from host" path, conntrack gives us
		 * CALI_CT_ESTABLISHED only. Better to fix the corner case here than on
		 * the generic path.
		 */
		ct_result_set_rc(ctx.state->ct_result.rc, CALI_CT_ESTABLISHED_DNAT);
		/* fallthrough */
	case CALI_CT_NEW:
		/* There is a conflict, this is the first packet that conflicts. By
		 * setting a NAT destination being the same as the original destination,
		 * we trigger a void/fake DNAT which will conflict on the source
		 * port and will trigger psnat.
		 */
		nat_dest_ident.addr = ctx.state->ip_dst;
		nat_dest_ident.port = ctx.state->dport;

		ctx.nat_dest = &nat_dest_ident;
		break;
	default:
		CALI_INFO("Unexpected CT result %d after host source port collision DENY.\n",
			  ct_result_rc(ctx.state->ct_result.rc));
		goto deny;
	}

	calico_tc_process_ct_lookup(&ctx);

	return forward_or_drop(&ctx);

deny:
	return TC_ACT_SHOT;
}

SEC("classifier/tc/drop")
int calico_tc_skb_drop(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering calico_tc_skb_drop - DENY\n");

	struct cali_tc_state *state;

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_DEBUG) {
		state = state_get();
		if (!state) {
			CALI_DEBUG("State map lookup failed: no event generated\n");
			return TC_ACT_SHOT;
		}
	}

	CALI_DEBUG("proto=%d\n", state->ip_proto);
	CALI_DEBUG("src=%x dst=%x\n", bpf_ntohl(state->ip_src), bpf_ntohl(state->ip_dst));
	CALI_DEBUG("pre_nat=%x:%d\n", bpf_ntohl(state->pre_nat_ip_dst), state->pre_nat_dport);
	CALI_DEBUG("post_nat=%x:%d\n", bpf_ntohl(state->post_nat_ip_dst), state->post_nat_dport);
	CALI_DEBUG("tun_ip=%x\n", state->tun_ip);
	CALI_DEBUG("pol_rc=%d\n", state->pol_rc);
	CALI_DEBUG("sport=%d\n", state->sport);
	CALI_DEBUG("flags=0x%x\n", state->flags);
	CALI_DEBUG("ct_rc=%d\n", state->ct_result.rc);

	return TC_ACT_SHOT;
}

#ifndef CALI_ENTRYPOINT_NAME
#define CALI_ENTRYPOINT_NAME calico_entrypoint
#endif

#define ENTRY_FUNC(x)				\
	SEC("classifier/"XSTR(x))		\
	int  x(struct __sk_buff *skb)		\
	{					\
		return calico_tc(skb);		\
	}

// Entrypoint with definable name.  It's useful to redefine the name for each entrypoint
// because the name is exposed by bpftool et al.

ENTRY_FUNC(CALI_ENTRYPOINT_NAME)

char ____license[] __attribute__((section("license"), used)) = "GPL";
