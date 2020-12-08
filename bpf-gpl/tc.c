// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
#include "log.h"
#include "skb.h"
#include "policy.h"
#include "conntrack.h"
#include "nat.h"
#include "routes.h"
#include "jump.h"
#include "reasons.h"
#include "icmp.h"
#include "arp.h"

#ifndef CALI_FIB_LOOKUP_ENABLED
#define CALI_FIB_LOOKUP_ENABLED true
#endif

#ifndef CALI_DROP_WORKLOAD_TO_HOST
#define CALI_DROP_WORKLOAD_TO_HOST false
#endif

#ifdef CALI_DEBUG_ALLOW_ALL

/* If we want to just compile the code without defining any policies and to
 * avoid compiling out code paths that are not reachable if traffic is denied,
 * we can compile it with allow all
 */
static CALI_BPF_INLINE enum calico_policy_result execute_policy_norm(struct __sk_buff *skb,
				__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	RULE_START(0);
	RULE_END(0, allow);

	return CALI_POL_NO_MATCH;
deny:
	return CALI_POL_DENY;
allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}
#else

static CALI_BPF_INLINE enum calico_policy_result execute_policy_norm(struct __sk_buff *skb,
				__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	RULE_START(0);
	RULE_END(0, deny);

	return CALI_POL_NO_MATCH;
deny:
	return CALI_POL_DENY;
allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

#endif /* CALI_DEBUG_ALLOW_ALL */

static CALI_BPF_INLINE struct cali_tc_state * state_get(void)
{
	__u32 key = 0;
	return cali_v4_state_lookup_elem(&key);
}

__attribute__((section("1/0")))
int calico_tc_norm_pol_tail(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering normal policy tail call\n");

	struct cali_tc_state *state = state_get();
	if (!state) {
	        CALI_DEBUG("State map lookup failed: DROP\n");
	        goto deny;
	}

	state->pol_rc = execute_policy_norm(skb, state->ip_proto, state->ip_src,
					    state->ip_dst, state->sport, state->dport);

	bpf_tail_call(skb, &cali_jump, EPILOGUE_PROG_INDEX);
	CALI_DEBUG("Tail call to post-policy program failed: DROP\n");

deny:
	return TC_ACT_SHOT;
}

struct fwd {
	int res;
	__u32 mark;
	enum calico_reason reason;
#if FIB_ENABLED
	__u32 fib_flags;
	bool fib;
#endif
};

#if FIB_ENABLED
#define fwd_fib(fwd)			((fwd)->fib)
#define fwd_fib_set(fwd, v)		((fwd)->fib = v)
#define fwd_fib_set_flags(fwd, flags)	((fwd)->fib_flags = flags)
#else
#define fwd_fib(fwd)	false
#define fwd_fib_set(fwd, v)
#define fwd_fib_set_flags(fwd, flags)
#endif

static CALI_BPF_INLINE struct fwd calico_tc_skb_accepted(struct __sk_buff *skb,
							 struct iphdr *ip_header,
							 struct cali_tc_state *state,
							 struct calico_nat_dest *nat_dest);

static CALI_BPF_INLINE int skb_nat_l4_csum_ipv4(struct __sk_buff *skb, size_t off,
						__be32 ip_from, __be32 ip_to,
						__u16 port_from, __u16 port_to,
						__u64 flags)
{
	int ret = 0;

	if (ip_from != ip_to) {
		CALI_DEBUG("L4 checksum update (csum is at %d) IP from %x to %x\n", off,
				bpf_ntohl(ip_from), bpf_ntohl(ip_to));
		ret = bpf_l4_csum_replace(skb, off, ip_from, ip_to, flags | BPF_F_PSEUDO_HDR | 4);
		CALI_DEBUG("bpf_l4_csum_replace(IP): %d\n", ret);
	}
	if (port_from != port_to) {
		CALI_DEBUG("L4 checksum update (csum is at %d) port from %d to %d\n",
				off, bpf_ntohs(port_from), bpf_ntohs(port_to));
		int rc = bpf_l4_csum_replace(skb, off, port_from, port_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(port): %d\n", rc);
		ret |= rc;
	}

	return ret;
}

static CALI_BPF_INLINE int forward_or_drop(struct __sk_buff *skb,
					   struct cali_tc_state *state,
					   struct fwd *fwd)
{
	int rc = fwd->res;
	enum calico_reason reason = fwd->reason;

	if (rc == TC_ACT_SHOT) {
		goto deny;
	}

	if (rc == CALI_RES_REDIR_BACK) {
		int redir_flags = 0;
		if  (CALI_F_FROM_HOST) {
			redir_flags = BPF_F_INGRESS;
		}

		/* Revalidate the access to the packet */
		if ((void *)(long)skb->data + sizeof(struct ethhdr) > (void *)(long)skb->data_end) {
			reason = CALI_REASON_SHORT;
			goto deny;
		}

		/* Swap the MACs as we are turning it back */
		struct ethhdr *eth_hdr = (void *)(long)skb->data;
		unsigned char mac[ETH_ALEN];
		__builtin_memcpy(mac, &eth_hdr->h_dest, ETH_ALEN);
		__builtin_memcpy(&eth_hdr->h_dest, &eth_hdr->h_source, ETH_ALEN);
		__builtin_memcpy(&eth_hdr->h_source, mac, ETH_ALEN);

		rc = bpf_redirect(skb->ifindex, redir_flags);
		if (rc == TC_ACT_REDIRECT) {
			CALI_DEBUG("Redirect to the same interface (%d) succeeded.\n", skb->ifindex);
			goto skip_fib;
		}

		CALI_DEBUG("Redirect to the same interface (%d) failed.\n", skb->ifindex);
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
		if ((void *)(long)skb->data + sizeof(struct ethhdr) > (void *)(long)skb->data_end) {
			reason = CALI_REASON_SHORT;
			goto deny;
		}
		/* Patch in the MAC addresses that should be set on the next hop. */
		struct ethhdr *eth_hdr = (void *)(long)skb->data;
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
	}

#if FIB_ENABLED
	// Try a short-circuit FIB lookup.
	if (fwd_fib(fwd)) {
		/* XXX we might include the tot_len in the fwd, set it once when
		 * we get the ip_header the first time and only adjust the value
		 * when we modify the packet - to avoid geting the header here
		 * again - it is simpler though.
		 */
		if (skb_too_short(skb)) {
			reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			goto deny;
		}

		struct iphdr *ip_header = skb_iphdr(skb);
		struct bpf_fib_lookup fib_params = {
			.family = 2, /* AF_INET */
			.tot_len = bpf_ntohs(ip_header->tot_len),
			.ifindex = skb->ingress_ifindex,
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
		rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), fwd->fib_flags);
		if (rc == 0) {
			CALI_DEBUG("FIB lookup succeeded\n");

			/* Since we are going to short circuit the IP stack on
			 * forward, check if TTL is still alive. If not, let the
			 * IP stack handle it. It was approved by policy, so it
			 * is safe.
			 */
			if ip_ttl_exceeded(ip_header) {
				rc = TC_ACT_UNSPEC;
				goto cancel_fib;
			}

			// Update the MACs.  NAT may have invalidated pointer into the packet so need to
			// revalidate.
			if ((void *)(long)skb->data + sizeof(struct ethhdr) > (void *)(long)skb->data_end) {
				reason = CALI_REASON_SHORT;
				goto deny;
			}
			struct ethhdr *eth_hdr = (void *)(long)skb->data;
			__builtin_memcpy(&eth_hdr->h_source, fib_params.smac, sizeof(eth_hdr->h_source));
			__builtin_memcpy(&eth_hdr->h_dest, fib_params.dmac, sizeof(eth_hdr->h_dest));

			// Redirect the packet.
			CALI_DEBUG("Got Linux FIB hit, redirecting to iface %d.\n", fib_params.ifindex);
			rc = bpf_redirect(fib_params.ifindex, 0);
			/* now we know we will bypass IP stack and ip->ttl > 1, decrement it! */
			if (rc == TC_ACT_REDIRECT) {
				ip_dec_ttl(ip_header);
			}
		} else if (rc < 0) {
			CALI_DEBUG("FIB lookup failed (bad input): %d.\n", rc);
			rc = TC_ACT_UNSPEC;
		} else {
			CALI_DEBUG("FIB lookup failed (FIB problem): %d.\n", rc);
			rc = TC_ACT_UNSPEC;
		}
	}

cancel_fib:
#endif /* FIB_ENABLED */

skip_fib:

	if (CALI_F_TO_HOST) {
		/* If we received the packet from the tunnel and we forward it to a
		 * workload we need to skip RPF check since there might be a better path
		 * for the packet if the host has multiple ifaces and might get dropped.
		 *
		 * XXX We should check ourselves that we got our tunnel packets only from
		 * XXX those devices where we expect them before we even decap.
		 */
		if (CALI_F_FROM_HEP && state->tun_ip != 0) {
			fwd->mark = CALI_SKB_MARK_SKIP_RPF;
		}
		/* Packet is towards host namespace, mark it so that downstream
		 * programs know that they're not the first to see the packet.
		 */
		CALI_DEBUG("Traffic is towards host namespace, marking with %x.\n", fwd->mark);
		/* FIXME: this ignores the mask that we should be using.
		 * However, if we mask off the bits, then clang spots that it
		 * can do a 16-bit store instead of a 32-bit load/modify/store,
		 * which trips up the validator.
		 */
		skb->mark = fwd->mark | CALI_SKB_MARK_SEEN; /* make sure that each pkt has SEEN mark */
	}

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		__u64 prog_end_time = bpf_ktime_get_ns();
		CALI_INFO("Final result=ALLOW (%d). Program execution time: %lluns\n",
				rc, prog_end_time-state->prog_start_time);
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

static CALI_BPF_INLINE int calico_tc(struct __sk_buff *skb)
{
	struct cali_tc_state *state;
	struct fwd fwd = {
		.res = TC_ACT_UNSPEC,
		.reason = CALI_REASON_UNKNOWN,
	};
	struct calico_nat_dest *nat_dest = NULL;
	nat_lookup_result nat_res = NAT_LOOKUP_ALLOW;

	state = state_get();
	if (!state) {
	        CALI_DEBUG("State map lookup failed: DROP\n");
		return TC_ACT_SHOT;
	}
	__builtin_memset(state, 0, sizeof(*state));

	/* We only try a FIB lookup and redirect for packets that are towards the host.
	 * For packets that are leaving the host namespace, routing has already been done.
	 */
	fwd_fib_set(&fwd, CALI_F_TO_HOST);

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		state->prog_start_time = bpf_ktime_get_ns();
	}
	state->tun_ip = 0;

#ifdef CALI_SET_SKB_MARK
	/* workaround for test since bpftool run cannot set it in context, wont
	 * be necessary if fixed in kernel
	 */
	skb->mark = CALI_SET_SKB_MARK;
#endif

	if (!CALI_F_TO_HOST && skb->mark == CALI_SKB_MARK_BYPASS) {
		CALI_DEBUG("Packet pre-approved by another hook, allow.\n");
		fwd.reason = CALI_REASON_BYPASS;
		goto allow;
	}

	struct iphdr *ip_header;
	if (CALI_F_TO_HEP || CALI_F_TO_WEP) {
		switch (skb->mark) {
		case CALI_SKB_MARK_BYPASS_FWD:
			CALI_DEBUG("Packet approved for forward.\n");
			fwd.reason = CALI_REASON_BYPASS;
			goto allow;
		case CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP:
			CALI_DEBUG("Packet approved for forward - src ip fixup\n");
			fwd.reason = CALI_REASON_BYPASS;

			/* we need to fix up the right src host IP */
			if (skb_too_short(skb)) {
				fwd.reason = CALI_REASON_SHORT;
				CALI_DEBUG("Too short\n");
				goto deny;
			}

			ip_header = skb_iphdr(skb);
			__be32 ip_src = ip_header->saddr;

			if (ip_src == HOST_IP) {
				CALI_DEBUG("src ip fixup not needed %x\n", bpf_ntohl(ip_src));
				goto allow;
			} else {
				CALI_DEBUG("src ip fixup %x\n", bpf_ntohl(HOST_IP));
			}

			/* XXX do a proper CT lookup to find this */
			ip_header->saddr = HOST_IP;
			int l3_csum_off = skb_iphdr_offset(skb) + offsetof(struct iphdr, check);

			int res = bpf_l3_csum_replace(skb, l3_csum_off, ip_src, HOST_IP, 4);
			if (res) {
				fwd.reason = CALI_REASON_CSUM_FAIL;
				goto deny;
			}

			goto allow;
		}
	}

	// Parse the packet.

	// TODO Do we need to handle any odd-ball frames here (e.g. with a 0 VLAN header)?
	switch (bpf_htons(skb->protocol)) {
	case ETH_P_IP:
		break;
	case ETH_P_ARP:
		CALI_DEBUG("ARP: allowing packet\n");
		fwd_fib_set(&fwd, false);
		goto allow;
	case ETH_P_IPV6:
		if (CALI_F_WEP) {
			CALI_DEBUG("IPv6 from workload: drop\n");
			return TC_ACT_SHOT;
		} else {
			// FIXME: support IPv6.
			CALI_DEBUG("IPv6 on host interface: allow\n");
			return TC_ACT_UNSPEC;
		}
	default:
		if (CALI_F_WEP) {
			CALI_DEBUG("Unknown ethertype (%x), drop\n", bpf_ntohs(skb->protocol));
			goto deny;
		} else {
			CALI_DEBUG("Unknown ethertype on host interface (%x), allow\n",
								bpf_ntohs(skb->protocol));
			return TC_ACT_UNSPEC;
		}
	}

	if (skb_too_short(skb)) {
		fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	ip_header = skb_iphdr(skb);
	/* N.B. we need to grab the eth header here, instead of in the vxlan
	 * decap branch, to make verifier happy.
	 */
	struct ethhdr *eth = (void *)(long)skb->data;

	/* N.B. we need to create the arp key here otherwise the number of
	 * states the verifier needs to inspect explodes.
	 */
	struct arp_key arpk = {
		.ip = ip_header->saddr,
		.ifindex = skb->ifindex,
	};

	if (dnat_should_decap() && is_vxlan_tunnel(ip_header)) {
		struct udphdr *udp_header = (void*)(ip_header+1);
		/* decap on host ep only if directly for the node */
		CALI_DEBUG("VXLAN tunnel packet to %x (host IP=%x)\n", ip_header->daddr, HOST_IP);
		if (rt_addr_is_local_host(ip_header->daddr) &&
				vxlan_udp_csum_ok(udp_header) &&
				vxlan_size_ok(skb, udp_header) &&
				vxlan_vni_is_valid(skb, udp_header) &&
				vxlan_vni(skb, udp_header) == CALI_VXLAN_VNI) {

			/* We update the map straight with the packet data, eth header is
			 * dst:src but the value is src:dst so it flips it automatically
			 * when we use it on xmit.
			 */
			cali_v4_arp_update_elem(&arpk, eth, 0);
			CALI_DEBUG("ARP update for ifindex %d ip %x\n", arpk.ifindex, bpf_ntohl(arpk.ip));

			state->tun_ip = ip_header->saddr;
			CALI_DEBUG("vxlan decap\n");
			if (vxlan_v4_decap(skb)) {
				fwd.reason = CALI_REASON_DECAP_FAIL;
				goto deny;
			}

			if (skb_too_short(skb)) {
				fwd.reason = CALI_REASON_SHORT;
				CALI_DEBUG("Too short after VXLAN decap\n");
				goto deny;
			}
			ip_header = skb_iphdr(skb);

			CALI_DEBUG("vxlan decap origin %x\n", bpf_ntohl(state->tun_ip));
		}
	}

	// Drop malformed IP packets
	if (ip_header->ihl < 5) {
		fwd.reason = CALI_REASON_IP_MALFORMED;
		CALI_DEBUG("Drop malformed IP packets\n");
		goto deny;
	} else if (ip_header->ihl > 5) {
		/* Drop packets with IP options from/to WEP.
		 * Also drop packets with IP options if the dest IP is not host IP
		 */
		if (CALI_F_WEP || (CALI_F_FROM_HEP && !rt_addr_is_local_host(ip_header->daddr))) {
			fwd.reason = CALI_REASON_IP_OPTIONS;
			CALI_DEBUG("Drop packets with IP options\n");
			goto deny;
		}
		CALI_DEBUG("Allow packets with IP options and dst IP = hostIP\n");
		goto allow;
	}
	// Setting all of these up-front to keep the verifier happy.
	struct tcphdr *tcp_header = (void*)(ip_header+1);
	struct udphdr *udp_header = (void*)(ip_header+1);
	struct icmphdr *icmp_header = (void*)(ip_header+1);

	tc_state_fill_from_iphdr(state, ip_header);

	switch (state->ip_proto) {
	case IPPROTO_TCP:
		// Re-check buffer space for TCP (has larger headers than UDP).
		if (!skb_has_data_after(skb, ip_header, sizeof(struct tcphdr))) {
			CALI_DEBUG("Too short for TCP: DROP\n");
			goto deny;
		}
		state->sport = bpf_ntohs(tcp_header->source);
		state->dport = bpf_ntohs(tcp_header->dest);
		CALI_DEBUG("TCP; ports: s=%d d=%d\n", state->sport, state->dport);
		break;
	case IPPROTO_UDP:
		state->sport = bpf_ntohs(udp_header->source);
		state->dport = bpf_ntohs(udp_header->dest);
		CALI_DEBUG("UDP; ports: s=%d d=%d\n", state->sport, state->dport);
		break;
	case IPPROTO_ICMP:
		icmp_header = (void*)(ip_header+1);
		CALI_DEBUG("ICMP; type=%d code=%d\n",
				icmp_header->type, icmp_header->code);
		break;
	case 4:
		// IPIP
		if (CALI_F_HEP) {
			// TODO IPIP whitelist.
			CALI_DEBUG("IPIP: allow\n");
			fwd_fib_set(&fwd, false);
			goto allow;
		}
	default:
		CALI_DEBUG("Unknown protocol (%d), unable to extract ports\n", (int)state->ip_proto);
	}

	state->pol_rc = CALI_POL_NO_MATCH;

	switch (state->ip_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		break;
	default:
		if (CALI_F_HEP) {
			// FIXME: allow unknown protocols through on host endpoints.
			goto allow;
		}
		// FIXME non-port based conntrack.
		goto deny;
	}

	struct ct_ctx ct_lookup_ctx = {
		.skb = skb,
		.proto	= state->ip_proto,
		.src	= state->ip_src,
		.sport	= state->sport,
		.dst	= state->ip_dst,
		.dport	= state->dport,
		.tun_ip = state->tun_ip,
	};

	if (state->ip_proto == IPPROTO_TCP) {
		if (!skb_has_data_after(skb, ip_header, sizeof(struct tcphdr))) {
			CALI_DEBUG("Too short for TCP: DROP\n");
			goto deny;
		}
		tcp_header = (void*)(ip_header+1);
		ct_lookup_ctx.tcp = tcp_header;
	}

	/* Do conntrack lookup before anything else */
	state->ct_result = calico_ct_v4_lookup(&ct_lookup_ctx);

	/* check if someone is trying to spoof a tunnel packet */
	if (CALI_F_FROM_HEP && ct_result_tun_src_changed(state->ct_result.rc)) {
		CALI_DEBUG("dropping tunnel pkt with changed source node\n");
		goto deny;
	}

	if (state->ct_result.flags & CALI_CT_FLAG_NAT_OUT) {
		state->flags |= CALI_ST_NAT_OUTGOING;
	}

	/* We are possibly past (D)NAT, but that is ok, we need to let the IP
	 * stack do the RPF check on the source, dest is not important.
	 */
	if (ct_result_rpf_failed(state->ct_result.rc)) {
		fwd_fib_set(&fwd, false);
	}

	/* skip policy if we get conntrack hit */
	if (ct_result_rc(state->ct_result.rc) != CALI_CT_NEW) {
		if (state->ct_result.flags & CALI_CT_FLAG_SKIP_FIB) {
			state->flags |= CALI_ST_SKIP_FIB;
		}
		goto skip_policy;
	}

	/* Unlike from WEP where we can do RPF by comparing to calico routing
	 * info, we must rely in Linux to do it for us when receiving packets
	 * from outside of the host. We enforce RPF failed on every new flow.
	 * This will make it to skip fib in calico_tc_skb_accepted()
	 */
	if (CALI_F_FROM_HEP) {
		ct_result_set_flag(state->ct_result.rc, CALI_CT_RPF_FAILED);
	}

	/* No conntrack entry, check if we should do NAT */
	nat_dest = calico_v4_nat_lookup2(state->ip_src, state->ip_dst,
					 state->ip_proto, state->dport,
					 state->tun_ip != 0, &nat_res);

	if (nat_res == NAT_FE_LOOKUP_DROP) {
		CALI_DEBUG("Packet is from an unauthorised source: DROP\n");
		fwd.reason = CALI_REASON_UNAUTH_SOURCE;
		goto deny;
	}
	if (nat_dest != NULL) {
		state->post_nat_ip_dst = nat_dest->addr;
		state->post_nat_dport = nat_dest->port;
	} else if (nat_res == NAT_NO_BACKEND) {
		/* send icmp port unreachable if there is no backend for a service */
		state->icmp_type = ICMP_DEST_UNREACH;
		state->icmp_code = ICMP_PORT_UNREACH;
		state->tun_ip = 0;
		goto icmp_send_reply;
	} else {
		state->post_nat_ip_dst = state->ip_dst;
		state->post_nat_dport = state->dport;
	}

	if (CALI_F_TO_WEP &&
			skb->mark != CALI_SKB_MARK_SEEN &&
			cali_rt_flags_local_host(cali_rt_lookup_flags(state->ip_src))) {
		/* Host to workload traffic always allowed.  We discount traffic that was
		 * seen by another program since it must have come in via another interface.
		 */
		CALI_DEBUG("Packet is from the host: ACCEPT\n");
		state->pol_rc = CALI_POL_ALLOW;
		goto skip_policy;
	}

	if (CALI_F_FROM_WEP) {
		/* Do RPF check since it's our responsibility to police that. */
		CALI_DEBUG("Workload RPF check src=%x skb iface=%d.\n",
				bpf_ntohl(state->ip_src), skb->ifindex);
		struct cali_rt *r = cali_rt_lookup(state->ip_src);
		if (!r) {
			CALI_INFO("Workload RPF fail: missing route.\n");
			goto deny;
		}
		if (!cali_rt_flags_local_workload(r->flags)) {
			CALI_INFO("Workload RPF fail: not a local workload.\n");
			goto deny;
		}
		if (r->if_index != skb->ifindex) {
			CALI_INFO("Workload RPF fail skb iface (%d) != route iface (%d)\n",
					skb->ifindex, r->if_index);
			goto deny;
		}

		// Check whether the workload needs outgoing NAT to this address.
		if (r->flags & CALI_RT_NAT_OUT) {
			if (!(cali_rt_lookup_flags(state->post_nat_ip_dst) & CALI_RT_IN_POOL)) {
				CALI_DEBUG("Source is in NAT-outgoing pool "
					   "but dest is not, need to SNAT.\n");
				state->flags |= CALI_ST_NAT_OUTGOING;
			}
		} if (!(r->flags & CALI_RT_IN_POOL)) {
			CALI_DEBUG("Source %x not in IP pool\n", bpf_ntohl(state->ip_src));
			r = cali_rt_lookup(state->post_nat_ip_dst);
			if (!r || !(r->flags & (CALI_RT_WORKLOAD | CALI_RT_HOST))) {
				CALI_DEBUG("Outside cluster dest %x\n", bpf_ntohl(state->post_nat_ip_dst));
				state->flags |= CALI_ST_SKIP_FIB;
			}
		}
	}
	/* icmp_type and icmp_code share storage with the ports; now we've used
	 * the ports set to 0 to do the conntrack lookup, we can set the ICMP fields
	 * for policy.
	 */
	if (state->ip_proto == IPPROTO_ICMP) {
		state->icmp_type = icmp_header->type;
		state->icmp_code = icmp_header->code;
	}


	state->pol_rc = CALI_POL_NO_MATCH;
	if (nat_dest) {
		state->nat_dest.addr = nat_dest->addr;
		state->nat_dest.port = nat_dest->port;
	} else {
		state->nat_dest.addr = 0;
		state->nat_dest.port = 0;
	}

	if (CALI_F_HEP) {
		/* We don't support host-endpoint policy yet, skip straight to
		 * the epilogue program.
		 */
		state->pol_rc = CALI_POL_ALLOW;
		goto skip_policy;
	}

	CALI_DEBUG("About to jump to policy program; lack of further "
			"logs means policy dropped the packet...\n");
	bpf_tail_call(skb, &cali_jump, POL_PROG_INDEX);
	CALI_DEBUG("Tail call to policy program failed: DROP\n");
	return TC_ACT_SHOT;

icmp_send_reply:
	bpf_tail_call(skb, &cali_jump, ICMP_PROG_INDEX);
	/* should not reach here */
	goto deny;

skip_policy:
	fwd = calico_tc_skb_accepted(skb, ip_header, state, nat_dest);

allow:
finalize:
	return forward_or_drop(skb, state, &fwd);
deny:
	fwd.res = TC_ACT_SHOT;
	goto finalize;
}

__attribute__((section("1/1")))
int calico_tc_skb_accepted_entrypoint(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering calico_tc_skb_accepted_entrypoint\n");
	struct iphdr *ip_header = NULL;
	if (skb_too_short(skb)) {
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	ip_header = skb_iphdr(skb);
	struct cali_tc_state *state = state_get();
	if (!state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		goto deny;
	}

	struct calico_nat_dest *nat_dest = NULL;
	struct calico_nat_dest nat_dest_2 = {
		.addr=state->nat_dest.addr,
		.port=state->nat_dest.port,
	};
	if (state->nat_dest.addr != 0) {
		nat_dest = &nat_dest_2;
	}

	struct fwd fwd = calico_tc_skb_accepted(skb, ip_header, state, nat_dest);
	return forward_or_drop(skb, state, &fwd);

deny:
	return TC_ACT_SHOT;
}

static CALI_BPF_INLINE struct fwd calico_tc_skb_accepted(struct __sk_buff *skb,
							 struct iphdr *ip_header,
							 struct cali_tc_state *state,
							 struct calico_nat_dest *nat_dest)
{
	CALI_DEBUG("Entering calico_tc_skb_accepted\n");

	enum calico_reason reason = CALI_REASON_UNKNOWN;
	int rc = TC_ACT_UNSPEC;
	bool fib = false;
	struct ct_ctx ct_nat_ctx = {};
	int ct_rc = ct_result_rc(state->ct_result.rc);
	bool ct_related = ct_result_is_related(state->ct_result.rc);
	__u32 seen_mark;
	size_t l4_csum_off = 0, l3_csum_off;

	CALI_DEBUG("src=%x dst=%x\n", bpf_ntohl(state->ip_src), bpf_ntohl(state->ip_dst));
	CALI_DEBUG("post_nat=%x:%d\n", bpf_ntohl(state->post_nat_ip_dst), state->post_nat_dport);
	CALI_DEBUG("tun_ip=%x\n", state->tun_ip);
	CALI_DEBUG("pol_rc=%d\n", state->pol_rc);
	CALI_DEBUG("sport=%d\n", state->sport);
	CALI_DEBUG("flags=%x\n", state->flags);
	CALI_DEBUG("ct_rc=%d\n", ct_rc);
	CALI_DEBUG("ct_related=%d\n", ct_related);

	// Set the dport to 0, to make sure conntrack entries for icmp is proper as we use
	// dport to hold icmp type and code
	if (state->ip_proto == IPPROTO_ICMP) {
		state->dport = 0;
	}

	if (CALI_F_FROM_WEP && (state->flags & CALI_ST_NAT_OUTGOING)) {
		// We are going to SNAT this traffic, using iptables SNAT so set the mark
		// to trigger that and leave the fib lookup disabled.
		seen_mark = CALI_SKB_MARK_NAT_OUT;
	} else {
		if (state->flags & CALI_ST_SKIP_FIB) {
			fib = false;
		} else if (CALI_F_TO_HOST && !ct_result_rpf_failed(state->ct_result.rc)) {
			// Non-SNAT case, allow FIB lookup only if RPF check passed.
			// Note: tried to pass in the calculated value from calico_tc but
			// hit verifier issues so recalculate it here.
			fib = true;
		}
		seen_mark = CALI_SKB_MARK_SEEN;
	}

	/* We check the ttl here to avoid needing complicated handling of
	 * related trafic back from the host if we let the host to handle it.
	 */
	CALI_DEBUG("ip->ttl %d\n", ip_header->ttl);
	if (ip_ttl_exceeded(ip_header)) {
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

	l3_csum_off = skb_iphdr_offset(skb) +  offsetof(struct iphdr, check);

	if (ct_related) {
		if (ip_header->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp;
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
				ip_header->saddr = state->ct_result.nat_ip;
				int res = bpf_l3_csum_replace(skb, l3_csum_off,
						state->ip_src, state->ct_result.nat_ip, 4);
				if (res) {
					reason = CALI_REASON_CSUM_FAIL;
					goto deny;
				}
				CALI_DEBUG("ICMP related: outer IP SNAT to %x\n",
						bpf_ntohl(state->ct_result.nat_ip));
			}

			if (!icmp_skb_get_hdr(skb, &icmp)) {
				CALI_DEBUG("Ooops, we already passed one such a check!!!\n");
				goto deny;
			}

			l3_csum_off += sizeof(*ip_header) + sizeof(*icmp);
			ip_header = (struct iphdr *)(icmp + 1); /* skip to inner ip */

			/* flip the direction, we need to reverse the original packet */
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

	struct tcphdr *tcp_header = (void*)(ip_header+1);
	struct udphdr *udp_header = (void*)(ip_header+1);

	__u8 ihl = ip_header->ihl * 4;

	int res = 0;
	bool encap_needed = false;

	if (state->ip_proto == IPPROTO_ICMP && ct_related) {
		/* do not fix up embedded L4 checksum for related ICMP */
	} else {
		switch (ip_header->protocol) {
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
			CALI_DEBUG("Implicitly denied by normal policy: DROP\n");
			goto deny;
		case CALI_POL_DENY:
			CALI_DEBUG("Denied by normal policy: DROP\n");
			goto deny;
		case CALI_POL_ALLOW:
			CALI_DEBUG("Allowed by normal policy: ACCEPT\n");
		}

		if (CALI_F_FROM_WEP &&
				CALI_DROP_WORKLOAD_TO_HOST &&
				cali_rt_flags_local_host(
					cali_rt_lookup_flags(state->post_nat_ip_dst))) {
			CALI_DEBUG("Workload to host traffic blocked by "
				   "DefaultEndpointToHostAction: DROP\n");
			goto deny;
		}

		ct_nat_ctx.skb = skb;
		ct_nat_ctx.proto = state->ip_proto;
		ct_nat_ctx.src = state->ip_src;
		ct_nat_ctx.sport = state->sport;
		ct_nat_ctx.dst = state->post_nat_ip_dst;
		ct_nat_ctx.dport = state->post_nat_dport;
		ct_nat_ctx.tun_ip = state->tun_ip;
		if (state->flags & CALI_ST_NAT_OUTGOING) {
			ct_nat_ctx.flags |= CALI_CT_FLAG_NAT_OUT;
		}
		if (CALI_F_FROM_WEP && state->flags & CALI_ST_SKIP_FIB) {
			ct_nat_ctx.flags |= CALI_CT_FLAG_SKIP_FIB;
		}

		if (state->ip_proto == IPPROTO_TCP) {
			if (!skb_has_data_after(skb, ip_header, sizeof(struct tcphdr))) {
				CALI_DEBUG("Too short for TCP: DROP\n");
				goto deny;
			}
			tcp_header = (void*)(ip_header+1);
			ct_nat_ctx.tcp = tcp_header;
		}

		// If we get here, we've passed policy.

		if (nat_dest == NULL) {
			if (conntrack_create(&ct_nat_ctx, CT_CREATE_NORMAL)) {
				CALI_DEBUG("Creating normal conntrack failed\n");

				if ((CALI_F_FROM_HEP && rt_addr_is_local_host(ct_nat_ctx.dst)) ||
						(CALI_F_TO_HEP && rt_addr_is_local_host(ct_nat_ctx.src))) {
					CALI_DEBUG("Allowing local host traffic without CT\n");
					goto allow;
				}

				goto deny;
			}
			goto allow;
		}

		ct_nat_ctx.orig_dst = state->ip_dst;
		ct_nat_ctx.orig_dport = state->dport;
		/* fall through as DNAT is now established */

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
			int nat_type = CT_CREATE_NAT;

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
							ct_nat_ctx.flags |= CALI_CT_FLAG_DSR_FWD;
						}
						ct_nat_ctx.flags |= CALI_CT_FLAG_NP_FWD;
					}

					nat_type = CT_CREATE_NAT_FWD;
					ct_nat_ctx.tun_ip = rt->next_hop;
					state->ip_dst = rt->next_hop;
				}
			}


			if (conntrack_create(&ct_nat_ctx, nat_type)) {
				CALI_DEBUG("Creating NAT conntrack failed\n");
				goto deny;
			}
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
					ip_is_dnf(ip_header) && vxlan_v4_encap_too_big(skb)) {
				CALI_DEBUG("Request packet with DNF set is too big\n");
				goto icmp_too_big;
			}
			state->ip_src = HOST_IP;
			seen_mark = CALI_SKB_MARK_SKIP_RPF;

			/* We cannot enforce RPF check on encapped traffic, do FIB if you can */
			fib = true;

			goto nat_encap;
		}

		ip_header->daddr = state->post_nat_ip_dst;

		switch (ip_header->protocol) {
		case IPPROTO_TCP:
			tcp_header->dest = bpf_htons(state->post_nat_dport);
			break;
		case IPPROTO_UDP:
			udp_header->dest = bpf_htons(state->post_nat_dport);
			break;
		}

		CALI_VERB("L3 csum at %d L4 csum at %d\n", l3_csum_off, l4_csum_off);

		if (l4_csum_off) {
			res = skb_nat_l4_csum_ipv4(skb, l4_csum_off, state->ip_dst,
					state->post_nat_ip_dst,	bpf_htons(state->dport),
					bpf_htons(state->post_nat_dport),
					ip_header->protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);
		}

		res |= bpf_l3_csum_replace(skb, l3_csum_off, state->ip_dst, state->post_nat_ip_dst, 4);

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
					ip_is_dnf(ip_header) && vxlan_v4_encap_too_big(skb)) {
				CALI_DEBUG("Return ICMP mtu is too big\n");
				goto icmp_too_big;
			}
		}

		// Actually do the NAT.
		ip_header->saddr = state->ct_result.nat_ip;

		switch (ip_header->protocol) {
		case IPPROTO_TCP:
			tcp_header->source = bpf_htons(state->ct_result.nat_port);
			break;
		case IPPROTO_UDP:
			udp_header->source = bpf_htons(state->ct_result.nat_port);
			break;
		}

		CALI_VERB("L3 csum at %d L4 csum at %d\n", l3_csum_off, l4_csum_off);

		if (l4_csum_off) {
			res = skb_nat_l4_csum_ipv4(skb, l4_csum_off, state->ip_src,
					state->ct_result.nat_ip, bpf_htons(state->sport),
					bpf_htons(state->ct_result.nat_port),
					ip_header->protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);
		}

		CALI_VERB("L3 checksum update (csum is at %d) port from %x to %x\n",
				l3_csum_off, state->ip_src, state->ct_result.nat_ip);

		int csum_rc = bpf_l3_csum_replace(skb, l3_csum_off,
						  state->ip_src, state->ct_result.nat_ip, 4);
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
			goto nat_encap;
		}

		state->sport = state->ct_result.nat_port;
		state->ip_src = state->ct_result.nat_ip;

		goto allow;

	case CALI_CT_ESTABLISHED_BYPASS:
		seen_mark = CALI_SKB_MARK_BYPASS;
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
	if (ip_frag_no(ip_header)) {
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
	bpf_tail_call(skb, &cali_jump, ICMP_PROG_INDEX);
	goto deny;

nat_encap:
	if (vxlan_v4_encap(skb, state->ip_src, state->ip_dst)) {
		reason = CALI_REASON_ENCAP_FAIL;
		goto  deny;
	}

	state->sport = state->dport = CALI_VXLAN_PORT;
	state->ip_proto = IPPROTO_UDP;

	CALI_DEBUG("vxlan return %d ifindex_fwd %d\n",
			dnat_return_should_encap(), state->ct_result.ifindex_fwd);
	if (dnat_return_should_encap() && state->ct_result.ifindex_fwd != CT_INVALID_IFINDEX) {
		rc = CALI_RES_REDIR_IFINDEX;
	}

allow:
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

__attribute__((section("1/2")))
int calico_tc_skb_send_icmp_replies(struct __sk_buff *skb)
{
	__u32 fib_flags = 0;
	int rc = TC_ACT_UNSPEC;
	enum calico_reason reason = CALI_REASON_UNKNOWN;
	__u32 seen_mark;
	struct fwd fwd;

	CALI_DEBUG("Entering calico_tc_skb_send_icmp_replies\n");
	if (skb_too_short(skb)) {
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	struct iphdr *ip_header = skb_iphdr(skb);
	struct cali_tc_state *state = state_get();
	if (!state) {
		CALI_DEBUG("State map lookup failed: DROP\n");
		goto deny;
	}
	CALI_DEBUG("ICMP type %d and code %d\n",state->icmp_type, state->icmp_code);

	if (state->icmp_code == ICMP_FRAG_NEEDED) {
		fib_flags |= BPF_FIB_LOOKUP_OUTPUT;
		if (CALI_F_FROM_WEP) {
			/* we know it came from workload, just send it back the same way */
			rc = CALI_RES_REDIR_BACK;
		}
	}

	if (icmp_v4_reply(skb, ip_header, state->icmp_type, state->icmp_code, state->tun_ip)) {
		fwd.res = TC_ACT_SHOT;
		fwd.reason = reason;
	} else {
		seen_mark = CALI_SKB_MARK_BYPASS_FWD;
		fwd.res = rc;
		fwd.mark = seen_mark;

		fwd_fib_set(&fwd, false);
		fwd_fib_set_flags(&fwd, fib_flags);
	}

	if (skb_too_short(skb)) {
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	ip_header = skb_iphdr(skb);
	tc_state_fill_from_iphdr(state, ip_header);
	state->sport = state->dport = 0;
	return forward_or_drop(skb, state, &fwd);
deny:
	return TC_ACT_SHOT;
}

#ifndef CALI_ENTRYPOINT_NAME
#define CALI_ENTRYPOINT_NAME calico_entrypoint
#endif

// Entrypoint with definable name.  It's useful to redefine the name for each entrypoint
// because the name is exposed by bpftool et al.
__attribute__((section(XSTR(CALI_ENTRYPOINT_NAME))))
int tc_calico_entry(struct __sk_buff *skb)
{
	return calico_tc(skb);
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
