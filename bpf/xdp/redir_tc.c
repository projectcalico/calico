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

#ifndef CALI_FIB_LOOKUP_ENABLED
#define CALI_FIB_LOOKUP_ENABLED true
#endif

enum calico_policy_result {
	CALI_POL_NO_MATCH,
	CALI_POL_ALLOW,
	CALI_POL_DENY,
};

static CALI_BPF_INLINE enum calico_policy_result execute_policy_norm(struct __sk_buff *skb,__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __NORMAL_POLICY__

	return CALI_POL_NO_MATCH;
	deny:
	return CALI_POL_DENY;
	allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALI_BPF_INLINE enum calico_policy_result execute_policy_aof(struct __sk_buff *skb,__u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __AOF_POLICY__

	return CALI_POL_NO_MATCH;
	deny:
	return CALI_POL_DENY;
	allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALI_BPF_INLINE enum calico_policy_result execute_policy_pre_dnat(struct __sk_buff *skb, __u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __PRE_DNAT_POLICY__

	return CALI_POL_NO_MATCH;
	deny:
	return CALI_POL_DENY;
	allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALI_BPF_INLINE enum calico_policy_result execute_policy_do_not_track(struct __sk_buff *skb, __u8 ip_proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
	if (!(flags & CALI_TC_HOST_EP) || !(flags & CALI_TC_INGRESS)) {
		return CALI_POL_NO_MATCH;
	}
	if ((skb->mark & CALI_SKB_MARK_SEEN_MASK) == CALI_SKB_MARK_SEEN) {
		return CALI_POL_NO_MATCH;
	}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __DO_NOT_TRACK_POLICY__

	return CALI_POL_NO_MATCH;
	deny:
	return CALI_POL_DENY;
	allow:
	return CALI_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALI_BPF_INLINE int calico_tc(struct __sk_buff *skb, enum calico_tc_flags flags) {
	enum calico_reason reason = CALI_REASON_UNKNOWN;
	uint64_t prog_start_time;
	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		prog_start_time = bpf_ktime_get_ns();
	}
	uint64_t timer_start_time = 0 , timer_end_time = 0;
	int rc = TC_ACT_UNSPEC;

	// Parse the packet.

	// TODO Do we need to handle any odd-ball frames here (e.g. with a 0 VLAN header)?
	switch (skb->protocol) {
	case be16_to_host(ETH_P_IP):
		break;
	case be16_to_host(ETH_P_ARP):
		CALI_DEBUG("ARP: allowing packet\n");
		goto allow_skip_fib;
	case be16_to_host(ETH_P_IPV6):
		if (!(flags & CALI_TC_HOST_EP)) {
			CALI_DEBUG("IPv6 from workload: drop\n");
			return TC_ACT_SHOT;
		} else {
			// FIXME: support IPv6.
			CALI_DEBUG("IPv6 on host interface: allow\n");
			return TC_ACT_UNSPEC;
		}
	default:
		if (!(flags & CALI_TC_HOST_EP)) {
			CALI_DEBUG("Unknown ethertype (%x), drop\n", be16_to_host(skb->protocol));
			goto deny;
		} else {
			CALI_DEBUG("Unknown ethertype on host interface (%x), allow\n", be16_to_host(skb->protocol));
			return TC_ACT_UNSPEC;
		}
	}

	struct ethhdr *eth_hdr;
	struct iphdr *ip_header;
	if (CALI_TC_FLAGS_IPIP_ENCAPPED(flags)) {
		// Ingress on an IPIP tunnel: skb is [ether|outer IP|inner IP|payload]
		if ((void *)(long)skb->data + sizeof(struct ethhdr) + 2*sizeof(struct iphdr) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
			CALI_DEBUG("Too short\n");
			reason = CALI_REASON_SHORT;
			goto deny;
		}
		eth_hdr = (void *)(long)skb->data;
		struct iphdr *ipip_header = (void *)(eth_hdr+1);
		ip_header = ipip_header+1;
		CALI_DEBUG("IPIP; inner s=%x d=%x\n", be32_to_host(ip_header->saddr), be32_to_host(ip_header->daddr));
	} else if (CALI_TC_FLAGS_L3(flags)) {
		// Egress on an IPIP tunnel: skb is [inner IP|payload]
		if ((void *)(long)skb->data + sizeof(struct iphdr) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
			CALI_DEBUG("Too short\n");
			reason = CALI_REASON_SHORT;
			goto deny;
		}
		ip_header = (void *)(long)skb->data;
		CALI_DEBUG("IP; (L3) s=%x d=%x\n", be32_to_host(ip_header->saddr), be32_to_host(ip_header->daddr));
	} else {
		// Normal L2 interface: skb is [ether|IP|payload]
		if ((void *)(long)skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
			CALI_DEBUG("Too short\n");
			reason = CALI_REASON_SHORT;
			goto deny;
		}
		eth_hdr = (void *)(long)skb->data;
		ip_header = (void *)(eth_hdr+1);
		CALI_DEBUG("IP; s=%x d=%x\n", be32_to_host(ip_header->saddr), be32_to_host(ip_header->daddr));
	}
	// TODO Deal with IP header with options.

	// Setting all of these up-front to keep the verifier happy.
	struct tcphdr *tcp_header = (void*)(ip_header+1);
	struct udphdr *udp_header = (void*)(ip_header+1);
	struct icmphdr *icmp_header = (void*)(ip_header+1);


	__u8 ip_proto = ip_header->protocol;

	struct bpf_fib_lookup fib_params = {
		.family = 2, /* AF_INET */
		.tot_len = be16_to_host(ip_header->tot_len),
		.ifindex = skb->ingress_ifindex,
	};

	__u16 sport;
	__u16 dport;

	switch (ip_proto) {
	case IPPROTO_TCP:
		// Re-check buffer space for TCP (has larger headers than UDP).
		if ((void*)(tcp_header+1) > (void *)(long)skb->data_end) {
			CALI_DEBUG("Too short for TCP: DROP\n");
			goto deny;
		}
		sport = be16_to_host(tcp_header->source);
		dport = be16_to_host(tcp_header->dest);
		CALI_DEBUG("TCP; ports: s=%d d=%d\n", sport, dport);
		break;
	case IPPROTO_UDP:
		udp_header = (void*)(ip_header+1);
		sport = be16_to_host(udp_header->source);
		dport = be16_to_host(udp_header->dest);
		CALI_DEBUG("UDP; ports: s=%d d=%d\n", sport, dport);
		break;
	case IPPROTO_ICMP:
		icmp_header = (void*)(ip_header+1);
		sport = 0;
		dport = 0;
		CALI_DEBUG("ICMP; ports: type=%d code=%d\n",
				icmp_header->type, icmp_header->code);
		break;
	case 4:
		// IPIP
		if (flags & CALI_TC_HOST_EP) {
			// TODO IPIP whitelist.
			CALI_DEBUG("IPIP: allow\n");
			goto allow_skip_fib;
		}
	default:
		CALI_DEBUG("Unknown protocol (%d), unable to extract ports\n", (int)ip_proto);
		sport = 0;
		dport = 0;
	}

	__be32 ip_src = ip_header->saddr;
	__be32 ip_dst = ip_header->daddr;
	enum calico_policy_result pol_rc = CALI_POL_NO_MATCH;
	if (CALI_TC_FLAGS_HOST_ENDPOINT(flags)) {
		// For host endpoints only, execute doNotTrack policy.
		pol_rc = execute_policy_do_not_track(
			skb, ip_proto, ip_src, ip_dst, sport, dport, flags);
		switch (pol_rc) {
		case CALI_POL_DENY:
			CALI_DEBUG("Denied by do-not-track policy: DROP\n");
			goto deny;
		case CALI_POL_ALLOW:
			CALI_DEBUG("Allowed by do-not-track policy: ACCEPT\n");
			goto allow;
		default:
			break;
		}
	}

	struct calico_ct_result ct_result;
	switch (ip_proto) {
	case IPPROTO_TCP:
		// Now, do conntrack lookup.
		ct_result = calico_ct_v4_tcp_lookup(ip_src, ip_dst, sport, dport, tcp_header, flags);
		break;
	case IPPROTO_UDP:
		ct_result = calico_ct_v4_udp_lookup(ip_src, ip_dst, sport, dport, flags);
		break;
	case IPPROTO_ICMP:
		ct_result = calico_ct_v4_icmp_lookup(ip_src, ip_dst, icmp_header, flags);
		break;
	default:
		goto deny;
	}

	switch (ct_result.rc){
	case CALI_CT_NEW:
		// New connection, apply policy.

		if (CALI_TC_FLAGS_HOST_ENDPOINT(flags)) {
			// Execute pre-DNAT policy.
			pol_rc = execute_policy_pre_dnat(skb, ip_proto, ip_src, ip_dst,  sport,  dport, flags);
			if (pol_rc == CALI_POL_DENY) {
				CALI_DEBUG("Denied by do-not-track policy: DROP\n");
				goto deny;
			} // Other RCs handled below.
		}

		// Do a NAT table lookup.
		struct calico_nat_dest *nat_dest = calico_v4_nat_lookup(ip_proto, ip_dst, dport, flags);
		__be32 post_nat_ip_dst;
		__u16 post_nat_dport;
		if (nat_dest != NULL) {
			// If the packet passes policy, we'll NAT it below, for now, just
			// update the dest IP/port for the policy lookup.
			post_nat_ip_dst = nat_dest->addr;
			post_nat_dport = nat_dest->port;
		} else {
			post_nat_ip_dst = ip_dst;
			post_nat_dport = dport;
		}

		if (pol_rc == CALI_POL_NO_MATCH) {
			// No match in pre-DNAT policy, apply normal policy.
			// TODO apply-on-forward policy
			if (false) {
				pol_rc = execute_policy_aof(skb, ip_proto, ip_src, post_nat_ip_dst,  sport,  post_nat_dport, flags);
			}
			pol_rc = execute_policy_norm(skb, ip_proto, ip_src, post_nat_ip_dst,  sport,  post_nat_dport, flags);
		}
		switch (pol_rc) {
		case CALI_POL_NO_MATCH:
			CALI_DEBUG("Implicitly denied by normal policy: DROP\n");
			goto deny;
		case CALI_POL_DENY:
			CALI_DEBUG("Denied by normal policy: DROP\n");
			goto deny;
		case CALI_POL_ALLOW:
			CALI_DEBUG("Allowed by normal policy: ACCEPT\n");
		}

		// If we get here, we've passed policy.
		if (nat_dest != NULL) {
			// Packet is to be NATted, need to record a NAT entry.
			switch (ip_proto) {
			case IPPROTO_TCP:
				if ((void*)(tcp_header+1) > (void *)(long)skb->data_end) {
					CALI_DEBUG("Too short for TCP: DROP\n");
					goto deny;
				}
				calico_ct_v4_tcp_create_nat(skb, ip_src, ip_dst, sport, dport, post_nat_ip_dst, post_nat_dport, tcp_header, flags);
				break;
			case IPPROTO_UDP:
				calico_ct_v4_udp_create_nat(skb, ip_src, ip_dst, sport, dport, post_nat_ip_dst, post_nat_dport, flags);
				break;
			case IPPROTO_ICMP:
				calico_ct_v4_icmp_create_nat(skb, ip_src, ip_dst, post_nat_ip_dst, flags);
				break;
			}

			// Actually do the NAT.
			ip_header->daddr = post_nat_ip_dst;
			size_t csum_offset;

			switch (ip_proto) {
			case IPPROTO_TCP:
				tcp_header->dest = host_to_be16(post_nat_dport);
				csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
				bpf_l4_csum_replace(skb, csum_offset, ip_dst, post_nat_ip_dst, BPF_F_PSEUDO_HDR | 4);
				bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  host_to_be16(post_nat_dport), 2);
				break;
			case IPPROTO_UDP:
				udp_header->dest = host_to_be16(post_nat_dport);
				csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
				bpf_l4_csum_replace(skb, csum_offset, ip_dst, post_nat_ip_dst, BPF_F_PSEUDO_HDR | 4);
				bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  host_to_be16(post_nat_dport), 2);
				break;
			}

			bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_dst, post_nat_ip_dst, 4);
		} else {
			// No NAT for this packet, record a simple entry.
			switch (ip_proto) {
			case IPPROTO_TCP:
				if ((void*)(tcp_header+1) > (void *)(long)skb->data_end) {
					CALI_DEBUG("Too short for TCP: DROP\n");
					goto deny;
				}
				calico_ct_v4_tcp_create(skb, ip_src, ip_dst, sport, dport, tcp_header, flags);
				break;
			case IPPROTO_UDP:
				calico_ct_v4_udp_create(skb, ip_src, ip_dst, sport, dport, flags);
				break;
			case IPPROTO_ICMP:
				calico_ct_v4_icmp_create(skb, ip_src, ip_dst, flags);
				break;
			}
		}

		fib_params.sport = sport;
		fib_params.dport = post_nat_dport;
		fib_params.ipv4_src = ip_src;
		fib_params.ipv4_dst = post_nat_ip_dst;

		goto allow;
	case CALI_CT_ESTABLISHED:
		fib_params.l4_protocol = ip_proto;
		fib_params.sport = sport;
		fib_params.dport = dport;
		fib_params.ipv4_src = ip_src;
		fib_params.ipv4_dst = ip_dst;

		goto allow;
	case CALI_CT_ESTABLISHED_DNAT:
		CALI_DEBUG("CT: DNAT to %x:%d\n", be32_to_host(ct_result.nat_ip), ct_result.nat_port);

		// Actually do the NAT.
		post_nat_ip_dst = ct_result.nat_ip;
		post_nat_dport = ct_result.nat_port;
		ip_header->daddr = post_nat_ip_dst;
		size_t csum_offset;

		switch (ip_proto) {
		case IPPROTO_TCP:
			tcp_header->dest = host_to_be16(post_nat_dport);
			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
			bpf_l4_csum_replace(skb, csum_offset, ip_dst, post_nat_ip_dst, BPF_F_PSEUDO_HDR | 4);
			bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  host_to_be16(post_nat_dport), 2);
			break;
		case IPPROTO_UDP:
			udp_header->dest = host_to_be16(post_nat_dport);
			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
			bpf_l4_csum_replace(skb, csum_offset, ip_dst, post_nat_ip_dst, BPF_F_PSEUDO_HDR | 4);
			bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport),  host_to_be16(post_nat_dport), 2);
			break;
		}

		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_dst, post_nat_ip_dst, 4);

		fib_params.sport = sport;
		fib_params.dport = post_nat_dport;
		fib_params.ipv4_src = ip_src;
		fib_params.ipv4_dst = post_nat_ip_dst;

		goto allow;
	case CALI_CT_ESTABLISHED_SNAT:
		CALI_DEBUG("CT: SNAT to %x:%d\n", be32_to_host(ct_result.nat_ip), ct_result.nat_port);

		// Actually do the NAT.
		ip_header->saddr = ct_result.nat_ip;

		switch (ip_proto) {
		case IPPROTO_TCP:
			tcp_header->source = host_to_be16(ct_result.nat_port);
			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
			break;
		case IPPROTO_UDP:
			udp_header->source = host_to_be16(ct_result.nat_port);
			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
			break;
		default:
			// ICMP has no checksum.
			goto skip_l4_csum;
		}

		bpf_l4_csum_replace(skb, csum_offset, ip_src, ct_result.nat_ip, BPF_F_PSEUDO_HDR | 4);
		bpf_l4_csum_replace(skb, csum_offset, host_to_be16(sport),  host_to_be16(ct_result.nat_port), 2);

	skip_l4_csum:
		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_src, ct_result.nat_ip, 4);

		fib_params.sport = ct_result.nat_port;
		fib_params.dport = dport;
		fib_params.ipv4_src = ct_result.nat_ip;
		fib_params.ipv4_dst = ip_dst;

		goto allow;
	default:
		if (CALI_TC_FLAGS_FROM_HOST_ENDPOINT(flags)) {
			// Since we're using the host endpoint program for TC-redirect acceleration for
			// workloads (but we haven't fully implemented host endpoint support yet), we can
			// get an incorrect conntrack invalid for host traffic.
			// FIXME: Properly handle host endpoint conntrack failures
			CALI_DEBUG("Traffic is towards host namespace but not conntracked, "
				"falling through to iptables\n");
			return TC_ACT_UNSPEC;
		} else {
			goto deny;
		}
	}

	// Try a short-circuit FIB lookup.
	allow:

	if (!CALI_TC_FLAGS_L3(flags) && CALI_FIB_LOOKUP_ENABLED && CALI_TC_FLAGS_TO_HOST(flags)) {
		CALI_DEBUG("Traffic is towards the host namespace, doing Linux FIB lookup\n");
		fib_params.l4_protocol = ip_proto;
		rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
		if (rc == 0) {
			CALI_DEBUG("FIB lookup succeeded\n");
			// Update the MACs.  NAT may have invalidated pointer into the packet so need to
			// revalidate.
			if ((void *)(long)skb->data + sizeof(struct ethhdr) > (void *)(long)skb->data_end) {
				CALI_DEBUG("BUG: packet got shorter?\n");
				reason = CALI_REASON_SHORT;
				goto deny;
			}
			eth_hdr = (void *)(long)skb->data;
			__builtin_memcpy(&eth_hdr->h_source, &fib_params.smac, sizeof(eth_hdr->h_source));
			__builtin_memcpy(&eth_hdr->h_dest, &fib_params.dmac, sizeof(eth_hdr->h_dest));

			// Redirect the packet.
			CALI_DEBUG("Got Linux FIB hit, redirecting to iface %d.\n", fib_params.ifindex);
			rc = bpf_redirect(fib_params.ifindex, 0);
		} else if (rc < 0) {
			CALI_DEBUG("FIB lookup failed (bad input): %d.\n", rc);
			rc = TC_ACT_UNSPEC;
		} else {
			CALI_DEBUG("FIB lookup failed (FIB problem): %d.\n", rc);
			rc = TC_ACT_UNSPEC;
		}
	}

	allow_skip_fib:
	if (CALI_TC_FLAGS_TO_HOST(flags)) {
		// Packet is towards host namespace, mark it so that downstream programs know that they're
		// not the first to see the packet.
		CALI_DEBUG("Traffic is towards host namespace, marking.\n");
		// FIXME: this ignores the mask that we should be using.  However, if we mask off the bits,
		// then clang spots that it can do a 16-bit store instead of a 32-bit load/modify/store,
		// which trips up the validator.
		skb->mark = CALI_SKB_MARK_SEEN;
	}

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		uint64_t prog_end_time = bpf_ktime_get_ns();
		CALI_INFO("Final result=ALLOW (%d). Program execution time: %lluns T: %lluns\n", rc, prog_end_time-prog_start_time, timer_end_time-timer_start_time);
	}
	return rc;

	deny:
	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		uint64_t prog_end_time = bpf_ktime_get_ns();
		CALI_INFO("Final result=DENY (%x). Program execution time: %lluns\n", reason, prog_end_time-prog_start_time);
	}
	return TC_ACT_SHOT;
}

// Handle packets that arrive at the host namespace from a workload.
__attribute__((section("calico_from_workload_ep")))
int tc_calico_from_workload(struct __sk_buff *skb) {
	return calico_tc(skb, 0);
}

// Handle packets that going to a workload from the host namespace..
__attribute__((section("calico_to_workload_ep")))
int tc_calico_to_workload(struct __sk_buff *skb) {
	return calico_tc(skb, CALI_TC_INGRESS);
}

// Handle packets that arrive at the host namespace from a host endpoint.
__attribute__((section("calico_from_host_ep")))
int tc_calico_from_host_endpoint(struct __sk_buff *skb) {
	return calico_tc(skb, CALI_TC_HOST_EP | CALI_TC_INGRESS);
}

// Handle packets that are leaving a host towards a host endpoint.
__attribute__((section("calico_to_host_ep")))
int tc_calico_to_host_endpoint(struct __sk_buff *skb) {
	return calico_tc(skb, CALI_TC_HOST_EP);
}

// Handle packets that arrive at the host namespace from a tunnel.
__attribute__((section("calico_from_tunnel_ep")))
int tc_calico_from_tunnel_endpoint(struct __sk_buff *skb) {
	return calico_tc(skb, CALI_TC_TUNNEL | CALI_TC_HOST_EP | CALI_TC_INGRESS);
}

// Handle packets that are leaving a host towards a tunnel.
__attribute__((section("calico_to_tunnel_ep")))
int tc_calico_to_tunnel_endpoint(struct __sk_buff *skb) {
	return calico_tc(skb, CALI_TC_TUNNEL | CALI_TC_HOST_EP);
}


char ____license[] __attribute__((section("license"), used)) = "GPL";
