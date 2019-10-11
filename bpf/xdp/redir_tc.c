// Copyright (c) 2019 Tigera, Inc. All rights reserved.

#include <asm/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <linux/bpf.h>
#include "../include/bpf.h"
#include "../include/log.h"
#include "../include/policy.h"
#include "../include/conntrack.h"
#include "../include/nat.h"
#include "bpf_maps.h"

enum calico_policy_result {
	CALICO_POL_NO_MATCH,
	CALICO_POL_ALLOW,
	CALICO_POL_DENY
};

struct port_range {
	__u64 ip_set_id;
	__u16 min, max;
};

struct cidr {
	__be32 mask, addr;
};


static CALICO_BPF_INLINE enum calico_policy_result execute_policy_norm(struct __sk_buff *skb,__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __NORMAL_POLICY__
	return CALICO_POL_ALLOW;

	return CALICO_POL_NO_MATCH;
	deny:
	return CALICO_POL_DENY;
	allow:
	return CALICO_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALICO_BPF_INLINE enum calico_policy_result execute_policy_aof(struct __sk_buff *skb,__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __AOF_POLICY__

	return CALICO_POL_NO_MATCH;
	deny:
	return CALICO_POL_DENY;
	allow:
	return CALICO_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALICO_BPF_INLINE enum calico_policy_result maybe_execute_policy_pre_dnat(struct __sk_buff *skb, __u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __PRE_DNAT_POLICY__

	return CALICO_POL_NO_MATCH;
	deny:
	return CALICO_POL_DENY;
	allow:
	return CALICO_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALICO_BPF_INLINE enum calico_policy_result maybe_execute_policy_do_not_track(struct __sk_buff *skb, __u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
	if (!(flags & CALICO_TC_HOST_EP) || !(flags & CALICO_TC_INGRESS)) {
		return CALICO_POL_NO_MATCH;
	}
	if ((skb->mark & CALICO_SKB_MARK_FROM_WORKLOAD_MASK) == CALICO_SKB_MARK_FROM_WORKLOAD) {
		return CALICO_POL_NO_MATCH;
	}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __DO_NOT_TRACK_POLICY__

	return CALICO_POL_NO_MATCH;
	deny:
	return CALICO_POL_DENY;
	allow:
	return CALICO_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALICO_BPF_INLINE int calico_tc_tcp(struct __sk_buff *skb, struct ethhdr *eth_hdr, struct iphdr *ip_header, enum calico_tc_flags flags, struct bpf_fib_lookup *fib_params) {
	// Re-check buffer space for TCP (has larger headers than UDP).
	CALICO_DEBUG_AT("Packet is TCP\n");
    struct tcphdr *tcp_header = (void*)(ip_header + 1);
	if ((void*)(tcp_header+1) > (void *)(long)skb->data_end) {
		CALICO_DEBUG_AT("Too short for TCP: DROP\n");
		return TC_ACT_SHOT;
	}

	// TODO Deal with IP header with options.

	__u16 sport = be16_to_host(tcp_header->source);
	__u16 dport = be16_to_host(tcp_header->dest);

	CALICO_DEBUG_AT("TCP; ports: s=%d d=%d\n", sport, dport);

	// For host endpoints, execute do-not-track policy (will be no-op for other endpoints).
	__be32 ip_src = ip_header->saddr;
	__be32 ip_dst = ip_header->daddr;
	enum calico_policy_result pol_rc = maybe_execute_policy_do_not_track(skb, IPPROTO_TCP, ip_src, ip_dst, sport, dport, flags);
	switch (pol_rc) {
	case CALICO_POL_DENY:
		CALICO_DEBUG_AT("Denied by do-not-track policy: DROP\n");
		return TC_ACT_SHOT;
	case CALICO_POL_ALLOW:
		CALICO_DEBUG_AT("Allowed by do-not-track policy: ACCEPT\n");
		return TC_ACT_UNSPEC;
	default:
		break;
	}

	// Now, do conntrack lookup.
	struct calico_ct_result ct_result = calico_ct_v4_tcp_lookup(ip_src, ip_dst, sport, dport, tcp_header);

	switch (ct_result.rc){
	case CALICO_CT_NEW:
		// New connection, apply policy.

		// Execute pre-DNAT policy.
		pol_rc = maybe_execute_policy_pre_dnat(skb, IPPROTO_TCP, ip_src, ip_dst,  sport,  dport, flags);
		if (pol_rc == CALICO_POL_DENY) {
			CALICO_DEBUG_AT("Denied by do-not-track policy: DROP\n");
			return TC_ACT_SHOT;
		} // Other RCs handled below.

		// Do a NAT table lookup.
		struct calico_nat_dest *nat_dest = calico_v4_nat_lookup(IPPROTO_TCP, ip_dst, dport, flags);
		__be32 post_nat_ip_dst;
		__u16 post_nat_dport;
		if (nat_dest != NULL) {
			// If the packet passes policy, we'll NAT it below, for now, just update the dest IP/port
			// for the policy lookup.
			post_nat_ip_dst = nat_dest->addr;
			post_nat_dport = nat_dest->port;
		} else {
			post_nat_ip_dst = ip_dst;
			post_nat_dport = dport;
		}

		if (pol_rc == CALICO_POL_NO_MATCH) {
			// No match in pre-DNAT policy, apply normal policy.
			// TODO apply-on-forward policy
			if (false) {
				pol_rc = execute_policy_aof(skb, IPPROTO_TCP, ip_src, ip_dst,  sport,  dport, flags);
			}
			pol_rc = execute_policy_norm(skb, IPPROTO_TCP, ip_src, ip_dst,  sport,  dport, flags);
		}
		switch (pol_rc) {
		case CALICO_POL_NO_MATCH:
			CALICO_DEBUG_AT("Implicitly denied by normal policy: DROP\n");
			return TC_ACT_SHOT;
		case CALICO_POL_DENY:
			CALICO_DEBUG_AT("Denied by normal policy: DROP\n");
			return TC_ACT_SHOT;
		case CALICO_POL_ALLOW:
			CALICO_DEBUG_AT("Allowed by normal policy: ACCEPT\n");
		}

		// If we get here, we've passed policy.
		if (nat_dest != NULL) {
			// Packet is to be NATted, need to record a NAT entry.
			calico_ct_v4_tcp_create_nat(ip_src, ip_dst, sport, dport, post_nat_ip_dst, post_nat_dport, tcp_header);

			// TODO NAT conntrack
		} else {
			// No NAT for this packet, record a simple entry.
			calico_ct_v4_tcp_create(ip_src, ip_dst, sport, dport, tcp_header);
		}

		return TC_ACT_UNSPEC;
	case CALICO_CT_ESTABLISHED:
		fib_params->l4_protocol = IPPROTO_TCP;
		fib_params->sport = sport;
		fib_params->dport = dport;
		fib_params->ipv4_src = ip_src;
		fib_params->ipv4_dst = ip_dst;

		return TC_ACT_UNSPEC;
	case CALICO_CT_ESTABLISHED_DNAT:
		CALICO_DEBUG_AT("CT: NAT\n");

		ip_header->daddr = ct_result.nat_ip;
		tcp_header->dest = ct_result.nat_port;

		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_dst, ct_result.nat_ip, 4);
		size_t csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
		bpf_l4_csum_replace(skb, csum_offset, ip_dst, ct_result.nat_ip, BPF_F_PSEUDO_HDR | 4);
		bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  ct_result.nat_port, 2);

		fib_params->l4_protocol = IPPROTO_TCP;
		fib_params->sport = sport;
		fib_params->dport = ct_result.nat_port;
		fib_params->ipv4_src = ip_src;
		fib_params->ipv4_dst = ct_result.nat_ip;

		return TC_ACT_UNSPEC;
	case CALICO_CT_ESTABLISHED_SNAT:
		CALICO_DEBUG_AT("CT: NAT\n");

		ip_header->saddr = ct_result.nat_ip;
		tcp_header->source = ct_result.nat_port;

		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_src, ct_result.nat_ip, 4);
		csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
		bpf_l4_csum_replace(skb, csum_offset, ip_src, ct_result.nat_ip, BPF_F_PSEUDO_HDR | 4);
		bpf_l4_csum_replace(skb, csum_offset, host_to_be16(sport),  ct_result.nat_port, 2);

		fib_params->l4_protocol = IPPROTO_TCP;
		fib_params->sport = ct_result.nat_port;
		fib_params->dport = dport;
		fib_params->ipv4_src = ct_result.nat_ip;
		fib_params->ipv4_dst = ip_dst;

		return TC_ACT_UNSPEC;
	case CALICO_CT_INVALID:
		return TC_ACT_SHOT;
	}
	return TC_ACT_SHOT;
}

static CALICO_BPF_INLINE int calico_tc(struct __sk_buff *skb, enum calico_tc_flags flags) {
	enum calico_reason reason = CALICO_REASON_UNKNOWN;
	uint64_t prog_start_time;
	if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_INFO) {
		prog_start_time = bpf_ktime_get_ns();
	}
	uint64_t timer_start_time = 0 , timer_end_time = 0;
	int rc = TC_ACT_UNSPEC;

	// Parse the packet.

    // TODO Do we need to handle any odd-ball frames here (e.g. with a 0 VLAN header)?
	if (skb->protocol != be16_to_host(ETH_P_IP)) {
		CALICO_DEBUG_AT("Skipping ethertype %x\n", skb->protocol);
		reason = CALICO_REASON_NOT_IP;
		goto allow_skip_fib;
	}
	CALICO_DEBUG_AT("Packet is IP\n");

    if ((void *)(long)skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
		CALICO_DEBUG_AT("Too short\n");
		reason = CALICO_REASON_SHORT;
		goto deny;
	}

    struct ethhdr *eth_hdr = (void *)(long)skb->data;
    struct iphdr *ip_header = (void *)(eth_hdr+1);

    CALICO_DEBUG_AT("IP; s=%x d=%x\n", be32_to_host(ip_header->saddr), be32_to_host(ip_header->daddr));

    __u8 ip_proto = ip_header->protocol;

    struct bpf_fib_lookup fib_params = {
		.family = 2, /* AF_INET */
		.tot_len = be16_to_host(ip_header->tot_len),
		.ifindex = skb->ingress_ifindex,
    };

	switch (ip_proto) {
	case IPPROTO_TCP:
		rc = calico_tc_tcp(skb, eth_hdr, ip_header, flags, &fib_params);
		break;
//	case IPPROTO_UDP:
//		CALICO_DEBUG_AT("Packet is UDP\n");
//		udp_header = (void*)(ip_header + 1);
//		sport = be16_to_host(udp_header->source);
//		dport = be16_to_host(udp_header->dest);
//		CALICO_DEBUG_AT("UDP; ports: s=%d d=%d\n", sport, dport);
//		break;
//	case IPPROTO_ICMP:
//		icmp_header = (void*)(ip_header + 1);
//		CALICO_DEBUG_AT("Packet is ICMP\n");
//		sport = 0;
//		dport = 0;
//		break;
	}

	if (rc == TC_ACT_SHOT) {
		goto deny;
	} else {
		goto allow;
	}

//	// doNotTrack policy is host endpoint only and it doesn't apply to traffic that was from a workload.
//	if ((flags & CALICO_TC_HOST_EP) &&
//			((flags & CALICO_TC_INGRESS) ||
//			 !((skb->mark & CALICO_SKB_MARK_FROM_WORKLOAD_MASK) == CALICO_SKB_MARK_FROM_WORKLOAD))) {
//		// TODO Include failsafe ports in policy
//		// TODO Whitelist our VXLAN/IPIP traffic (or just include it in the do-not-track policy)?
//
//		// Execute do-not-track policy.
//		uint64_t pol_start_time;
//		CALICO_DEBUG_AT("Applying doNotTrack policy.\n");
//		if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_DEBUG) pol_start_time = bpf_ktime_get_ns();
//		enum calico_policy_result do_not_track_rc = execute_policy_do_not_track(
//				ip_header, sport, dport, flags);
//		if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_DEBUG) {
//			uint64_t pol_end_time = bpf_ktime_get_ns();
//			CALICO_DEBUG_AT("Do-not-track policy execution time: %lluns\n", pol_end_time-pol_start_time);
//		}
//		if (do_not_track_rc == CALICO_POL_DENY) {
//			CALICO_DEBUG_AT("Denied by do-not-track policy.\n");
//			reason = CALICO_REASON_DNT;
//			goto deny;
//		}
//		if (do_not_track_rc == CALICO_POL_ALLOW) {
//			CALICO_DEBUG_AT("Allowed by do-not-track policy\n");
//			skb->mark |= CALICO_SKB_MARK_NO_TRACK; // Mark packet so our iptables rule can actually disable conntrack.
//			reason = CALICO_REASON_DNT;
//			goto allow;
//		}
//		CALICO_DEBUG_AT("No match in do-not-track policy\n");
//		// else CALICO_POL_NO_MATCH, fall through to next stage...
//	}
//
//	if (!connOpener && (skb->mark & CALICO_SKB_MARK_FROM_WORKLOAD_MASK) == CALICO_SKB_MARK_FROM_WORKLOAD) {
//		CALICO_DEBUG_AT("CT: Allow - already checked by ingress hook\n");
//		reason = CALICO_REASON_CT;
//		goto allow;
//	}
//
//	// Now do a lookup in our connection tracking table.
//	struct calico_ct_key ct_key = {
//		.dst_addr = orig_ip_dst,
//		.src_addr = orig_ip_src,
//		.src_port = sport,
//		.dst_port = dport,
//		.protocol = ip_proto,
//	};
//
//	struct calico_ct_key ct_rev_key = {};
//
//	// Skip conntrack lookup for the SYN packet.
//	struct calico_ct_value *ct_data = NULL;
//	if (!connOpener) {
//		ct_data = bpf_map_lookup_elem(&calico_ct_map_v4, &ct_key);
//	}
//	if (ct_data) {
//		// Got a conntrack hit.
//		if (ct_data->ct_type == CALICO_CT_TYPE_ALLOW) {
//			if (connCloser) {
//				// FIXME proper conntrack fin/rst handling.
//				CALICO_DEBUG_AT("CT: FIN/RST deleting conntrack entry\n");
//				bpf_map_delete_elem(&calico_ct_map_v4, &ct_key);
//			}
//			CALICO_DEBUG_AT("CT: Allow\n");
//			reason = CALICO_REASON_CT;
//			goto allow;
//		} else if (ct_data->ct_type == CALICO_CT_TYPE_NAT) {
//			CALICO_DEBUG_AT("CT: NAT\n");
//			reason = CALICO_REASON_CT_NAT;
//
//			bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), orig_ip_src, ct_data->data.ct_nat.src_addr, 4);
//			bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), orig_ip_dst, ct_data->data.ct_nat.dst_addr, 4);
//			int csum_offset;
//			switch (ip_proto) {
//			case IPPROTO_TCP:
//				csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
//				if (orig_ip_src != ct_data->data.ct_nat.src_addr)
//					bpf_l4_csum_replace(skb, csum_offset, orig_ip_src, ct_data->data.ct_nat.src_addr, BPF_F_PSEUDO_HDR | 4);
//				if (orig_ip_dst != ct_data->data.ct_nat.dst_addr)
//					bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, ct_data->data.ct_nat.dst_addr, BPF_F_PSEUDO_HDR | 4);
//				if (host_to_be16(sport) != ct_data->data.ct_nat.src_port)
//					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(sport),  ct_data->data.ct_nat.src_port, 2);
//				if (host_to_be16(dport) != ct_data->data.ct_nat.dst_port)
//					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  ct_data->data.ct_nat.dst_port, 2);
//
//				eth_hdr = (void *)(long)skb->data;
//				ip_header = (void *)(eth_hdr+1);
//				tcp_header = (void*)(ip_header + 1);
//
//				if (tcp_header + 1 > (void *)(long)skb->data_end) {
//					CALICO_DEBUG_AT("Too short\n");
//					goto deny;
//				}
//				tcp_header->source =ct_data->data.ct_nat.src_port;
//				tcp_header->dest = ct_data->data.ct_nat.dst_port;
//				break;
//			case IPPROTO_UDP:
//				csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
//				if (orig_ip_src != ct_data->data.ct_nat.src_addr)
//					bpf_l4_csum_replace(skb, csum_offset, orig_ip_src, ct_data->data.ct_nat.src_addr, BPF_F_PSEUDO_HDR | 4);
//				if (orig_ip_dst != ct_data->data.ct_nat.dst_addr)
//					bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, ct_data->data.ct_nat.dst_addr, BPF_F_PSEUDO_HDR | 4);
//				if (host_to_be16(sport) != ct_data->data.ct_nat.src_port)
//					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(sport),  ct_data->data.ct_nat.src_port, 2);
//				if (host_to_be16(dport) != ct_data->data.ct_nat.dst_port)
//					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  ct_data->data.ct_nat.dst_port, 2);
//
//				eth_hdr = (void *)(long)skb->data;
//				ip_header = (void *)(eth_hdr+1);
//				udp_header = (void *)(ip_header + 1);
//
//				if (udp_header + 1 > (void *)(long)skb->data_end) {
//					CALICO_DEBUG_AT("Too short\n");
//					goto deny;
//				}
//				udp_header->source = ct_data->data.ct_nat.src_addr;
//				udp_header->dest = ct_data->data.ct_nat.src_addr;
//				break;
//			case IPPROTO_ICMP:
//				// ICMP checksum doesn't use a pseudo header so no need to update it.
//				/* no break */
//			default:
//				eth_hdr = (void *)(long)skb->data;
//				ip_header = (void *)(eth_hdr+1);
//
//				if (((void*)(ip_header+1)) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
//					CALICO_DEBUG_AT("Too short\n");
//					goto deny;
//				}
//			};
//			ip_header->saddr = ct_data->data.ct_nat.src_addr;
//			ip_header->daddr = ct_data->data.ct_nat.dst_addr;
//
//			goto allow;
//		} else {
//			CALICO_DEBUG_AT("CT: Unknown %d\n", ct_data->ct_type);
//			reason = CALICO_REASON_CT;
//			goto deny;
//		}
//	} else {
//		CALICO_DEBUG_AT("CT: Miss\n");
//	}
//
//	struct calico_nat_v4_value *nat_val;
//	if (((flags & CALICO_TC_HOST_EP) && (flags & CALICO_TC_INGRESS)) ||
//			(!(flags & CALICO_TC_HOST_EP) && !(flags & CALICO_TC_INGRESS))) {
//		// Now, for traffic towards the host, do a lookup in the NAT table to see if we should NAT this packet.
//		struct calico_nat_v4_key nat_key = {};
//		nat_key.addr = ip_header->daddr;
//		nat_key.port = dport;
//		nat_key.protocol = ip_proto;
//
//
//		timer_start_time = bpf_ktime_get_ns();
//		nat_val = bpf_map_lookup_elem(&calico_nat_map_v4, &nat_key);
//		CALICO_DEBUG_AT("NAT: 1st level lookup addr=%x port=%x protocol=%x.\n", (int)be32_to_host(nat_key.addr), (int)be16_to_host(nat_key.port), (int)(nat_key.protocol));
//	} else {
//		nat_val = NULL;
//	}
//	struct calico_nat_dest *nat2_val = NULL;
//	if (nat_val) {
//		// This destination requires DNAT.  Look up the second-level table.
//		struct calico_nat_secondary_v4_key nat2_key;
//		nat2_key.id = nat_val->id;
//		nat2_key.ordinal = bpf_get_prandom_u32() % nat_val->count;
//		CALICO_DEBUG_AT("NAT: 1st level hit; id=%d ordinal=%d\n", nat2_key.id, nat2_key.ordinal);
//
//		nat2_val = bpf_map_lookup_elem(&calico_nat_secondary_map_v4, &nat2_key);
//	} else {
//		CALICO_DEBUG_AT("NAT: 1st level miss\n");
//	}
//	struct calico_ct_value ct_value = {}, ct_rev_value = {};
//	if (nat2_val) {
//		CALICO_DEBUG_AT("NAT: 2nd level hit addr=%x port=%d\n", (int)be32_to_host(nat2_val->addr), (int)be16_to_host(nat2_val->port));
//		// FIXME Proper offset calculation.
//
//		// l[34]_csum_replace invalidate our pointers into the packet.  Each case below needs to
//		// recalculate and bounds check the pointers to keep the verifier happy.
//		// TODO: maybe we can defer checksum update until the very end to avoid having to revalidate?
//
//		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_header->daddr, nat2_val->addr, 4);
//		int csum_offset;
//		switch (ip_proto) {
//		case IPPROTO_TCP:
//			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
//			bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, nat2_val->addr, 4);
//			bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport), nat2_val->port, 2);
//
//			eth_hdr = (void *)(long)skb->data;
//			ip_header = (void *)(eth_hdr+1);
//			tcp_header = (void*)(ip_header + 1);
//
//			if (tcp_header + 1 > (void *)(long)skb->data_end) {
//				CALICO_DEBUG_AT("Too short\n");
//				goto deny;
//			}
//			tcp_header->dest = nat2_val->port;
//			break;
//		case IPPROTO_UDP:
//			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
//			bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, nat2_val->addr, 4);
//			bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport), nat2_val->port, 2);
//
//			eth_hdr = (void *)(long)skb->data;
//			ip_header = (void *)(eth_hdr+1);
//			udp_header = (void *)(ip_header + 1);
//
//			if (udp_header + 1 > (void *)(long)skb->data_end) {
//				CALICO_DEBUG_AT("Too short\n");
//				goto deny;
//			}
//			udp_header->dest = nat2_val->port;
//			break;
//		case IPPROTO_ICMP:
//			// ICMP checksum doesn't use a pseudo header so no need to update it.
//			// bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum), orig_ip_dst, nat2_val->addr, 4);
//			/* no break */
//		default:
//			eth_hdr = (void *)(long)skb->data;
//			ip_header = (void *)(eth_hdr+1);
//
//			if (((void*)(ip_header+1)) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
//				CALICO_DEBUG_AT("Too short\n");
//				goto deny;
//			}
//		};
//		ip_header->daddr = nat2_val->addr;
//
//		// Did a NAT, set up the reverse conntrack key accordingly.
//		ct_rev_key.src_addr = nat2_val->addr;
//		ct_rev_key.src_port = be16_to_host(nat2_val->port);
//		ct_rev_key.dst_addr = orig_ip_src;
//		ct_rev_key.dst_port = sport;
//		ct_rev_key.protocol = ip_proto;
//
//		CALICO_DEBUG_AT("CT rev key src=%x dst=%x\n", ct_rev_key.src_addr , ct_rev_key.dst_addr);
//		CALICO_DEBUG_AT("CT rev key sport=%x dport=%x\n", ct_rev_key.src_port, ct_rev_key.dst_port);
//		ct_value.ct_type = CALICO_CT_TYPE_NAT;
//		ct_value.data.ct_nat.src_addr = orig_ip_src;
//		ct_value.data.ct_nat.src_port = host_to_be16(sport);
//		ct_value.data.ct_nat.dst_addr = nat2_val->addr;
//		ct_value.data.ct_nat.dst_port = nat2_val->port;
//		ct_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
//
//		ct_rev_value.ct_type = CALICO_CT_TYPE_NAT;
//		ct_rev_value.data.ct_nat.src_addr = orig_ip_dst;
//		ct_rev_value.data.ct_nat.src_port = host_to_be16(dport);
//		ct_rev_value.data.ct_nat.dst_addr = orig_ip_src;
//		ct_rev_value.data.ct_nat.dst_port = host_to_be16(sport);
//		ct_rev_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
//		timer_end_time = bpf_ktime_get_ns();
//	} else {
//		// Did not do a DNAT, set up the reverse conntrack key accordingly.
//		ct_rev_key.dst_addr = orig_ip_src;
//		ct_rev_key.src_addr = orig_ip_dst;
//		ct_rev_key.src_port = dport;
//		ct_rev_key.dst_port = sport;
//		ct_rev_key.protocol = ip_proto;
//
//		ct_value.ct_type = CALICO_CT_TYPE_ALLOW;
//		ct_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
//		ct_rev_value.ct_type = CALICO_CT_TYPE_ALLOW;
//		ct_rev_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
//	}
//
//	// Check whether the traffic is to a local IP on this host or not.
//	enum calico_policy_result norm_rc;
//
//	if (flags & CALICO_TC_HOST_EP) {
//		__be32 *ip = (flags & CALICO_TC_INGRESS) ? &ip_header->daddr : &ip_header->saddr;
//		if (bpf_map_lookup_elem(&calico_local_ips, ip)) {
//			// IP is local, apply normal policy.
//			CALICO_DEBUG_AT("Local destination, using normal rules.\n");
//			norm_rc = execute_policy_norm(ip_header, sport, dport, flags);
//		} else {
//			CALICO_DEBUG_AT("Remote destination, using apply-on-forward rules.\n");
//			norm_rc = execute_policy_aof(ip_header, sport, dport, flags);
//		}
//	} else {
//		CALICO_DEBUG_AT("Workload: applying normal policy.\n");
//		norm_rc = execute_policy_norm(ip_header, sport, dport, flags);
//	}
//
//
//	switch (norm_rc) {
//	case CALICO_POL_ALLOW:
//		CALICO_DEBUG_AT("Match: Allowed by normal/apply-on-forward policy\n");
//		reason = CALICO_REASON_POL;
//		break;
//	case CALICO_POL_DENY:
//		CALICO_DEBUG_AT("Match: Explicitly denied by normal/apply-on-forward policy.\n");
//		reason = CALICO_REASON_POL;
//		goto deny;
//	default:
//		CALICO_DEBUG_AT("Match: Implicitly denied by normal/apply-on-forward policy.\n");
//		reason = CALICO_REASON_POL;
//		goto deny;
//	}
//
//	// If we get here, packet was allowed, record it in conntrack.
//
//	bpf_map_update_elem(&calico_ct_map_v4, &ct_key, &ct_value, 0);
//	bpf_map_update_elem(&calico_ct_map_v4, &ct_rev_key, &ct_rev_value, 0);
//

	// Try a short-circuit FIB lookup.
	allow:

	if (((flags & CALICO_TC_HOST_EP) && (flags & CALICO_TC_INGRESS)) ||
			(!(flags & CALICO_TC_HOST_EP) && !(flags & CALICO_TC_INGRESS))) {
		CALICO_DEBUG_AT("Traffic is towards the host namespace, doing Linux FIB lookup\n");
		rc =  bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
		if (rc == 0) {
			CALICO_DEBUG_AT("FIB lookup succeeded\n");
			// Update the MACs.  NAT may have invalidated pointer into the packet so need to
			// revalidate.
		    if ((void *)(long)skb->data + sizeof(struct ethhdr) > (void *)(long)skb->data_end) {
				CALICO_DEBUG_AT("BUG: packet got shorter?\n");
				reason = CALICO_REASON_SHORT;
				goto deny;
			}
		    eth_hdr = (void *)(long)skb->data;
			__builtin_memcpy(&eth_hdr->h_source, &fib_params.smac, sizeof(eth_hdr->h_source));
			__builtin_memcpy(&eth_hdr->h_dest, &fib_params.dmac, sizeof(eth_hdr->h_dest));

			// Redirect the packet.
			CALICO_DEBUG_AT("Got Linux FIB hit, redirecting to iface %d.\n",fib_params.ifindex);
			rc = bpf_redirect(fib_params.ifindex, 0);
		} else if (rc < 0) {
			CALICO_DEBUG_AT("FIB lookup failed (bad input): %d.\n", rc);
			rc = TC_ACT_UNSPEC;
		} else {
			CALICO_DEBUG_AT("FIB lookup failed (FIB problem): %d.\n", rc);
			rc = TC_ACT_UNSPEC;
		}
	}

	allow_skip_fib:
	if (!(flags & CALICO_TC_HOST_EP) && !(flags & CALICO_TC_INGRESS)) {
		// Packet is leaving workload, mark it so any downstream programs know this traffic was from a workload.
		skb->mark |= CALICO_SKB_MARK_FROM_WORKLOAD;
	}

	if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_INFO) {
		uint64_t prog_end_time = bpf_ktime_get_ns();
		CALICO_INFO_AT("Final result=ALLOW (%x). Program execution time: %lluns T: %lluns\n", reason, prog_end_time-prog_start_time, timer_end_time-timer_start_time);
	}
	return rc;

	deny:
	if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_INFO) {
		uint64_t prog_end_time = bpf_ktime_get_ns();
		CALICO_INFO_AT("Final result=DENY (%x). Program execution time: %lluns\n", reason, prog_end_time-prog_start_time);
	}
	return TC_ACT_SHOT;
}

// Handle packets that arrive at the host namespace from a workload.
__attribute__((section("calico_from_workload")))
int tc_calico_from_workload(struct __sk_buff *skb) {
	return calico_tc(skb, 0);
}

// Handle packets that going to a workload from the host namespace..
__attribute__((section("calico_to_workload")))
int tc_calico_to_workload(struct __sk_buff *skb) {
	return calico_tc(skb, CALICO_TC_INGRESS);
}

// Handle packets that arrive at the host namespace from a host endpoint.
__attribute__((section("calico_from_host_endpoint")))
int tc_calico_from_host_endpoint(struct __sk_buff *skb) {
	return calico_tc(skb, CALICO_TC_HOST_EP | CALICO_TC_INGRESS);
}

// Handle packets that are leaving a host towards a host endpoint.
__attribute__((section("calico_to_host_endpoint")))
int tc_calico_to_host_endpoint(struct __sk_buff *skb) {
	return calico_tc(skb, CALICO_TC_HOST_EP);
}


char ____license[] __attribute__((section("license"), used)) = "GPL";
