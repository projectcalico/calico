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
#include "bpf_maps.h"

enum calico_tc_flags {
	CALICO_TC_HOST_EP = 1<<0,
	CALICO_TC_INGRESS = 1<<1,
};

#define CALICO_LOG_LEVEL_NONE 0
#define CALICO_LOG_LEVEL_INFO 5
#define CALICO_LOG_LEVEL_DEBUG 10

#ifndef CALICO_LOG_LEVEL
#define CALICO_LOG_LEVEL CALICO_LOG_LEVEL_INFO
#endif

#define CALICO_USE_LINUX_FIB true

#define LOG(__fmt, ...) do { \
		char fmt[] = __fmt; \
		bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
} while (0)

#define CALICO_INFO(fmt, ...)  LOG_LEVEL(CALICO_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define CALICO_DEBUG(fmt, ...) LOG_LEVEL(CALICO_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)

#define CALICO_INFO_AT(fmt, ...) \
	LOG_LEVEL_FLG(CALICO_LOG_LEVEL_INFO, flags, fmt, ## __VA_ARGS__)
#define CALICO_DEBUG_AT(fmt, ...) \
	LOG_LEVEL_FLG(CALICO_LOG_LEVEL_DEBUG, flags, fmt, ## __VA_ARGS__)

#define LOG_LEVEL(level, fmt, ...) do { \
	if (CALICO_LOG_LEVEL >= (level))    \
		LOG(fmt, ## __VA_ARGS__);          \
} while (0)

#define LOG_LEVEL_FLG(level, flags, fmt, ...) do { \
	if (CALICO_LOG_LEVEL >= (level))    \
		LOG_FLG(flags, fmt, ## __VA_ARGS__);          \
} while (0)

#define LOG_FLG(flags, fmt, ...) do { \
	if (((flags) & CALICO_TC_HOST_EP) && ((flags) & CALICO_TC_INGRESS)) { \
		LOG("HI: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALICO_TC_HOST_EP) { \
		LOG("HE: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALICO_TC_INGRESS) { \
		LOG("WI: " fmt, ## __VA_ARGS__); \
	} else { \
		LOG("WE: " fmt, ## __VA_ARGS__); \
	} \
} while (0)

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


#define RULE_MATCH(id, test, negate) do { \
		if ((negate) ? (test) : !(test)) { \
			/* Match failed, skip to next rule. */ \
			CALICO_DEBUG_AT("  rule didn't match -> fall through\n"); \
			goto rule_no_match_ ## id; \
		} \
	} while (false)

#define RULE_MATCH_PROTOCOL(id, negate, protocol_number) \
	CALICO_DEBUG_AT("  check protocol %d (pkt) == %d (rule)\n", (int)ip_header->protocol, (int)protocol_number); \
	RULE_MATCH(id, (protocol_number) == ip_header->protocol, negate)

#define RULE_MATCH_PORT_RANGES(id, negate, saddr_or_daddr, sport_or_dport, ...) do { \
		struct port_range port_ranges[] = {__VA_ARGS__}; \
		bool match = false; \
		_Pragma("clang loop unroll(full)") \
		for (int i = 0; i < (sizeof(port_ranges)/sizeof(struct port_range)); i++) { \
			if (port_ranges[i].ip_set_id == 0) {\
				/* Normal port match*/ \
				CALICO_DEBUG_AT("  check " #sport_or_dport " against %d <= %d (pkt) <= %d\n", (int)port_ranges[i].min, (int)(sport_or_dport)->port, (int)port_ranges[i].max); \
				if ((sport_or_dport)->port >= port_ranges[i].min && (sport_or_dport)->port <= port_ranges[i].max) { \
					match = true; \
					break; \
				} \
			} else {\
				/* Named port match; actually maps through to an IP set */ \
				CALICO_DEBUG_AT("  look up " #saddr_or_daddr ":port (%x:%d) in IP set %llx\n", \
						        be32_to_host(ip_header->saddr_or_daddr), (int)(sport_or_dport)->port, port_ranges[i].ip_set_id); \
				union ip4_set_bpf_lpm_trie_key k; \
				k.ip.mask = sizeof(struct ip4setkey)*8 ; \
				k.ip.set_id = host_to_be64(port_ranges[i].ip_set_id); \
				k.ip.addr = ip_header->saddr_or_daddr; \
				k.ip.port = (sport_or_dport)->port; \
				k.ip.protocol = ip_header->protocol; \
				k.ip.pad = 0; \
				if (bpf_map_lookup_elem(&calico_ip_sets, &k)) { \
					match=true; \
					break; \
				} \
			}\
		} \
		RULE_MATCH(id, match, negate); \
	} while (false)

#define RULE_MATCH_CIDRS(id, negate, saddr_or_daddr, ...) do { \
		struct cidr cidrs[] = {__VA_ARGS__}; \
		bool match = false; \
		_Pragma("clang loop unroll(full)") \
		for (int i = 0; i < (sizeof(cidrs)/sizeof(struct cidr)); i++) { \
			if ((ip_header->saddr_or_daddr & host_to_be32(cidrs[i].mask)) == \
			      host_to_be32(cidrs[i].addr)) { \
				match = true; \
				break; \
			} \
		} \
		RULE_MATCH(id, match, negate); \
	} while (false)

#define RULE_MATCH_IP_SET(id, negate, saddr_or_daddr, ip_set_id) do { \
		CALICO_DEBUG_AT("  look up " #saddr_or_daddr " (%x) in IP set " #ip_set_id "\n", be32_to_host(ip_header->saddr_or_daddr)); \
		bool match = false; \
		union ip4_set_bpf_lpm_trie_key k; \
		k.ip.mask = sizeof(struct ip4setkey)*8 ; \
		k.ip.set_id = host_to_be64(ip_set_id); \
		k.ip.addr = ip_header->saddr_or_daddr; \
		k.ip.protocol = 0; \
		k.ip.port = 0; \
		k.ip.pad = 0; \
		if (bpf_map_lookup_elem(&calico_ip_sets, &k)) { \
			match=true; \
		} \
		RULE_MATCH(id, match, negate); \
	} while (false)


#define RULE_START(id) \
	CALICO_DEBUG_AT("Rule " #id " \n");

#define RULE_END(id, action) \
	CALICO_DEBUG_AT("  MATCH -> " #action "\n"); \
	goto action; /* Reach here if the rule matched. */ \
	rule_no_match_ ## id: do {;} while (false)


static CALICO_BPF_INLINE enum calico_policy_result execute_policy_norm(struct iphdr *ip_header, struct protoport *sport, struct protoport *dport, enum calico_tc_flags flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-label"

	// __NORMAL_POLICY__

	return CALICO_POL_NO_MATCH;
	deny:
	return CALICO_POL_DENY;
	allow:
	return CALICO_POL_ALLOW;
#pragma clang diagnostic pop
}

static CALICO_BPF_INLINE enum calico_policy_result execute_policy_aof(struct iphdr *ip_header, struct protoport *sport, struct protoport *dport, enum calico_tc_flags flags) {
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

static CALICO_BPF_INLINE enum calico_policy_result execute_policy_pre_dnat(struct iphdr *ip_header, struct protoport *sport, struct protoport *dport, enum calico_tc_flags flags) {
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

static CALICO_BPF_INLINE enum calico_policy_result execute_policy_do_not_track(struct iphdr *ip_header, struct protoport *sport, struct protoport *dport, enum calico_tc_flags flags) {
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

#pragma clang diagnostic ignored "-Wunused-function"
static CALICO_BPF_INLINE enum calico_policy_result execute_policy_map(void *pol_map, struct iphdr *ip_header, __be32 *addr, struct protoport *sport, struct protoport *dport, enum calico_tc_flags flags) {
	struct calico_policy *pol;
	union ip4_bpf_lpm_trie_key key;

	CALICO_DEBUG_AT("Applying policy map; doing lookup on IP: %x.\n", be32_to_host(*addr));

	key.lpm.prefixlen = 32;
	__builtin_memcpy(&key.lpm.data, addr, 4);
	pol = bpf_map_lookup_elem(pol_map, &key);
	if (pol) {
		size_t opIdx = 0;
#pragma clang loop unroll(full)
		for (int i = 0; i < CALICO_NUM_POL_OPS; i++) {
			struct calico_policy_op *curOp;
			if (opIdx >=0 && opIdx <CALICO_NUM_POL_OPS) {
				curOp = &pol->ops[opIdx];
				bool match = false;
				switch (curOp->match_type & CALICO_MATCH_MASK_ACTION) {
				case CALICO_MATCH_DENY:
					return CALICO_POL_DENY;
				case CALICO_MATCH_ALLOW:
					return CALICO_POL_ALLOW;
				case CALICO_MATCH_SRC_PORT:
					match = curOp->port_range.min <= sport->port && curOp->port_range.max >= sport->port;
					break;
				case CALICO_MATCH_DEST_PORT:
					match = curOp->port_range.min <= dport->port && curOp->port_range.max >= dport->port;
					break;
				case CALICO_MATCH_PROTOCOL:
					match = ip_header->protocol == curOp->protocol;
					break;
				case CALICO_MATCH_SRC_IP:
				    match = (ip_header->saddr & curOp->ip_match.mask) == curOp->ip_match.addr;
				    break;
				case CALICO_MATCH_DEST_IP:
				    match = (ip_header->saddr & curOp->ip_match.mask) == curOp->ip_match.addr;
				    break;
				case CALICO_MATCH_SRC_IP_SET:
				{
		            union ip4_set_bpf_lpm_trie_key k;
				    k.ip.mask = 12;
				    k.ip.set_id = curOp->ip_set_id;
				    k.ip.addr = ip_header->saddr;
				    if (bpf_map_lookup_elem(&calico_ip_sets, &k)) {
				        match=true;
				    }
				    break;
				}
				case CALICO_MATCH_DEST_IP_SET:
				{
				    union ip4_set_bpf_lpm_trie_key k;
				    k.ip.mask = 12;
				    k.ip.set_id = curOp->ip_set_id;
				    k.ip.addr = ip_header->daddr;
				    if (bpf_map_lookup_elem(&calico_ip_sets, &k)) {
				        match=true;
				    }
				    break;
				}
				}

				if (curOp->match_type & CALICO_MATCH_NEGATE ? !match : match) {
					opIdx += 1;
				} else {
					opIdx += curOp->jump_no_match;
				}
			}
		}
	}
	return CALICO_POL_NO_MATCH;
}

static CALICO_BPF_INLINE int calico_tc(struct __sk_buff *skb, enum calico_tc_flags flags) {
	enum calico_reason reason = CALICO_REASON_UNKNOWN;
	uint64_t prog_start_time = bpf_ktime_get_ns();
	uint64_t timer_start_time = 0 , timer_end_time = 0;
	int rc = TC_ACT_UNSPEC;

	// Parse the packet.

    // TODO Do we need to handle any odd-ball frames here (e.g. with a 0 VLAN header)?
	if (skb->protocol != be16_to_host(ETH_P_IP)) {
		CALICO_DEBUG_AT("Skipping ethertype %x\n", skb->protocol);
		reason = CALICO_REASON_NOT_IP;
		goto allow_no_fib;
	}
	CALICO_DEBUG_AT("Packet is IP\n");

    if ((void *)(long)skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
		CALICO_DEBUG_AT("Too short\n");
		reason = CALICO_REASON_SHORT;
		goto deny;
	}

    struct ethhdr *eth_hdr = (void *)(long)skb->data;
    struct iphdr *ip_header = (void *)(eth_hdr+1);
    struct protoport sport = {};
    struct protoport dport = {};

    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;

	__be32 orig_ip_src = ip_header->saddr;
	__be32 orig_ip_dst = ip_header->daddr;
	__u8 ip_proto = ip_header->protocol;

	bool connOpener = false;

	switch (sport.proto = dport.proto = ip_header->protocol) {
	case IPPROTO_TCP:
		// Re-check buffer space for TCP (has larger headers than UDP).
		CALICO_DEBUG_AT("Packet is TCP\n");
		tcp_header = (void*)(ip_header + 1);
		if ((void*)(tcp_header+1) > (void *)(long)skb->data_end) {
			CALICO_DEBUG_AT("Too short for TCP\n");
			reason = CALICO_REASON_SHORT;
			goto deny;
		}

		// FIXME Deal with IP header with options.
		connOpener = tcp_header->syn && ! tcp_header->ack;

		sport.port = be16_to_host(tcp_header->source);
		dport.port = be16_to_host(tcp_header->dest);
		CALICO_DEBUG_AT("TCP; ports: %d %d\n", sport.port, dport.port);
		break;
	case IPPROTO_UDP:
		CALICO_DEBUG_AT("Packet is UDP\n");
		udp_header = (void*)(ip_header + 1);
		sport.port = be16_to_host(udp_header->source);
		dport.port = be16_to_host(udp_header->dest);
		CALICO_DEBUG_AT("UDP; ports: %d %d\n", sport.port, dport.port);
		break;
	case IPPROTO_ICMP:
		icmp_header = (void*)(ip_header + 1);
		CALICO_DEBUG_AT("Packet is ICMP\n");
		sport.port = 0;
		dport.port = 0;
		break;
	}

	// doNotTrack policy is host endpoint only and it doesn't apply to traffic that was from a workload.
	if ((flags & CALICO_TC_HOST_EP) &&
			((flags & CALICO_TC_INGRESS) ||
			 !(skb->mark & CALICO_SKB_MARK_FROM_WORKLOAD))) {
		CALICO_DEBUG_AT("Applying failsafe ports.\n");

		// Check failsafe ports.
		struct protoport *local_port = (flags & CALICO_TC_INGRESS) ? &dport : &sport;

		// FIXME Need to only do failsafes for local IP.
		// FIXME Conntrack for failsafes?
		if (bpf_map_lookup_elem(&calico_failsafe_ports, local_port)) {
			CALICO_DEBUG_AT("Packet is to/from a failsafe port.\n");
			reason = CALICO_REASON_FAILSAFE;
			goto allow;
		}

		// TODO Whitelist our VXLAN/IPIP traffic (or just include it in the do-not-track policy)?

		// Execute do-not-track policy.
		uint64_t pol_start_time;
		CALICO_DEBUG_AT("Applying doNotTrack policy.\n");
		if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_DEBUG) pol_start_time = bpf_ktime_get_ns();
		enum calico_policy_result do_not_track_rc = execute_policy_do_not_track(
				ip_header,
				&sport,
				&dport,
				flags);
		if (CALICO_LOG_LEVEL >= CALICO_LOG_LEVEL_DEBUG) {
			uint64_t pol_end_time = bpf_ktime_get_ns();
			CALICO_DEBUG_AT("FH: Do-not-track policy execution time: %lluns\n", pol_end_time-pol_start_time);
		}
		if (do_not_track_rc == CALICO_POL_DENY) {
			CALICO_DEBUG_AT("Denied by do-not-track policy.\n");
			reason = CALICO_REASON_DNT;
			goto deny;
		}
		if (do_not_track_rc == CALICO_POL_ALLOW) {
			CALICO_DEBUG_AT("Allowed by do-not-track policy\n");
			skb->mark |= CALICO_SKB_MARK_NO_TRACK; // Mark packet so our iptables rule can actually disable conntrack.
			reason = CALICO_REASON_DNT;
			goto allow;
		}
		CALICO_DEBUG_AT("No match in do-not-track policy\n");
		// else CALICO_POL_NO_MATCH, fall through to next stage...
	}

	// Now do a lookup in our connection tracking table.
	struct calico_ct_key ct_key = {};
	struct calico_ct_key ct_rev_key = {};
	ct_key.dst_addr = orig_ip_dst;
	ct_key.src_addr = orig_ip_src;
	ct_key.src_port = sport.port;
	ct_key.dst_port = dport.port;
	ct_key.protocol = ip_header->protocol;

	// TODO Avoid double conntrack lookup when both pods on same host
	// Skip conntrack lookup for the SYN packet.
	struct calico_ct_value *ct_data = NULL;
	if (!connOpener) {
		ct_data = bpf_map_lookup_elem(&calico_ct_map_v4, &ct_key);
	}
	if (ct_data && (
			((flags & CALICO_TC_HOST_EP) && (ct_data->flags & CALICO_CT_F_HOST_APPROVED)) ||
			(!(flags & CALICO_TC_HOST_EP) && (ct_data->flags & CALICO_CT_F_WORKLOAD_APPROVED))
		)) {
		// Got a conntrack hit that has been approved by this policy hook.  Short-circuit further processing.
		// TODO When we get a conntrack hit from another layer, update the entry after we make our policy decision.
		if (ct_data->ct_type == CALICO_CT_TYPE_ALLOW) {
			CALICO_DEBUG_AT("CT: Allow\n");
			reason = CALICO_REASON_CT;
			goto allow;
		} else if (ct_data->ct_type == CALICO_CT_TYPE_NAT) {
			CALICO_DEBUG_AT("CT: NAT\n");
			reason = CALICO_REASON_CT_NAT;

			bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), orig_ip_src, ct_data->data.ct_nat.src_addr, 4);
			bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), orig_ip_dst, ct_data->data.ct_nat.dst_addr, 4);
			int csum_offset;
			switch (ip_proto) {
			case IPPROTO_TCP:
				csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
				if (orig_ip_src != ct_data->data.ct_nat.src_addr)
					bpf_l4_csum_replace(skb, csum_offset, orig_ip_src, ct_data->data.ct_nat.src_addr, BPF_F_PSEUDO_HDR | 4);
				if (orig_ip_dst != ct_data->data.ct_nat.dst_addr)
					bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, ct_data->data.ct_nat.dst_addr, BPF_F_PSEUDO_HDR | 4);
				if (host_to_be16(sport.port) != ct_data->data.ct_nat.src_port)
					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(sport.port),  ct_data->data.ct_nat.src_port, 2);
				if (host_to_be16(dport.port) != ct_data->data.ct_nat.dst_port)
					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport.port),  ct_data->data.ct_nat.dst_port, 2);

				eth_hdr = (void *)(long)skb->data;
				ip_header = (void *)(eth_hdr+1);
				tcp_header = (void*)(ip_header + 1);

				if (tcp_header + 1 > (void *)(long)skb->data_end) {
					CALICO_DEBUG_AT("Too short\n");
					goto deny;
				}
				tcp_header->source =ct_data->data.ct_nat.src_port;
				tcp_header->dest = ct_data->data.ct_nat.dst_port;
				break;
			case IPPROTO_UDP:
				csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
				if (orig_ip_src != ct_data->data.ct_nat.src_addr)
					bpf_l4_csum_replace(skb, csum_offset, orig_ip_src, ct_data->data.ct_nat.src_addr, BPF_F_PSEUDO_HDR | 4);
				if (orig_ip_dst != ct_data->data.ct_nat.dst_addr)
					bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, ct_data->data.ct_nat.dst_addr, BPF_F_PSEUDO_HDR | 4);
				if (host_to_be16(sport.port) != ct_data->data.ct_nat.src_port)
					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(sport.port),  ct_data->data.ct_nat.src_port, 2);
				if (host_to_be16(dport.port) != ct_data->data.ct_nat.dst_port)
					bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport.port),  ct_data->data.ct_nat.dst_port, 2);

				eth_hdr = (void *)(long)skb->data;
				ip_header = (void *)(eth_hdr+1);
				udp_header = (void *)(ip_header + 1);

				if (udp_header + 1 > (void *)(long)skb->data_end) {
					CALICO_DEBUG_AT("Too short\n");
					goto deny;
				}
				udp_header->source = ct_data->data.ct_nat.src_addr;
				udp_header->dest = ct_data->data.ct_nat.src_addr;
				break;
			case IPPROTO_ICMP:
				// ICMP checksum doesn't use a pseudo header so no need to update it.
				/* no break */
			default:
				eth_hdr = (void *)(long)skb->data;
				ip_header = (void *)(eth_hdr+1);

				if (((void*)(ip_header+1)) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
					CALICO_DEBUG_AT("Too short\n");
					goto deny;
				}
			};
			ip_header->saddr = ct_data->data.ct_nat.src_addr;
			ip_header->daddr = ct_data->data.ct_nat.dst_addr;

			goto allow;
		} else {
			CALICO_DEBUG_AT("CT: Unknown %d\n", ct_data->ct_type);
			reason = CALICO_REASON_CT;
			goto deny;
		}
	} else {
		CALICO_DEBUG_AT("CT: Miss\n");
	}

	// If we get here, we don't have an approved conntrack entry.

	if ((flags & CALICO_TC_HOST_EP) && !(skb->mark & CALICO_SKB_MARK_FROM_WORKLOAD)) {
		// execute the pre-DNAT policy.
		enum calico_policy_result pre_dnat_rc = execute_policy_pre_dnat(
				ip_header,
				&sport,
				&dport,
				flags);
		if (pre_dnat_rc == CALICO_POL_ALLOW) {
			CALICO_DEBUG_AT("Allowed by pre-DNAT policy\n");
			reason = CALICO_REASON_PREDNAT;
			// TODO conntrack for pre-DNAT policy
			goto allow;
		}
		if (pre_dnat_rc == CALICO_POL_DENY) {
			CALICO_DEBUG_AT("Denied by pre-DNAT policy.\n");
			reason = CALICO_REASON_PREDNAT;
			goto deny;
		}
		// else CALICO_POL_NO_MATCH, fall through to next stage...
	}

	struct calico_nat_v4_value *nat_val;
	if (((flags & CALICO_TC_HOST_EP) && (flags & CALICO_TC_INGRESS)) ||
			(!(flags & CALICO_TC_HOST_EP) && !(flags & CALICO_TC_INGRESS))) {
		// Now, for traffic towards the host, do a lookup in the NAT table to see if we should NAT this packet.
		struct calico_nat_v4_key nat_key = {};
		nat_key.addr = ip_header->daddr;
		nat_key.port = dport.port;
		nat_key.protocol = dport.proto;


		timer_start_time = bpf_ktime_get_ns();
		nat_val = bpf_map_lookup_elem(&calico_nat_map_v4, &nat_key);
		CALICO_DEBUG_AT("NAT: 1st level lookup addr=%x port=%x protocol=%x.\n", (int)be32_to_host(nat_key.addr), (int)be16_to_host(nat_key.port), (int)(nat_key.protocol));
	} else {
		nat_val = NULL;
	}
	struct calico_nat_secondary_v4_value *nat2_val = NULL;
	if (nat_val) {
		// This destination requires DNAT.  Look up the second-level table.
		struct calico_nat_secondary_v4_key nat2_key;
		nat2_key.id = nat_val->id;
		nat2_key.ordinal = bpf_get_prandom_u32() % nat_val->count;
		CALICO_DEBUG_AT("NAT: 1st level hit; id=%d ordinal=%d\n", nat2_key.id, nat2_key.ordinal);

		nat2_val = bpf_map_lookup_elem(&calico_nat_secondary_map_v4, &nat2_key);
	} else {
		CALICO_DEBUG_AT("NAT: 1st level miss\n");
	}
	struct calico_ct_value ct_value = {}, ct_rev_value = {};
	if (nat2_val) {
		CALICO_DEBUG_AT("NAT: 2nd level hit addr=%x port=%d\n", (int)be32_to_host(nat2_val->addr), (int)be16_to_host(nat2_val->port));
		// FIXME Proper offset calculation.

		// l[34]_csum_replace invalidate our pointers into the packet.  Each case below needs to
		// recalculate and bounds check the pointers to keep the verifier happy.
		// TODO: maybe we can defer checksum update until the very end to avoid having to revalidate?

		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), ip_header->daddr, nat2_val->addr, 4);
		int csum_offset;
		switch (ip_proto) {
		case IPPROTO_TCP:
			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
			bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, nat2_val->addr, 4);
			bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport.port), nat2_val->port, 2);

			eth_hdr = (void *)(long)skb->data;
			ip_header = (void *)(eth_hdr+1);
			tcp_header = (void*)(ip_header + 1);

			if (tcp_header + 1 > (void *)(long)skb->data_end) {
				CALICO_DEBUG_AT("Too short\n");
				goto deny;
			}
			tcp_header->dest = nat2_val->port;
			break;
		case IPPROTO_UDP:
			csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
			bpf_l4_csum_replace(skb, csum_offset, orig_ip_dst, nat2_val->addr, 4);
			bpf_l4_csum_replace(skb, csum_offset, host_to_be16(dport.port), nat2_val->port, 2);

			eth_hdr = (void *)(long)skb->data;
			ip_header = (void *)(eth_hdr+1);
			udp_header = (void *)(ip_header + 1);

			if (udp_header + 1 > (void *)(long)skb->data_end) {
				CALICO_DEBUG_AT("Too short\n");
				goto deny;
			}
			udp_header->dest = nat2_val->port;
			break;
		case IPPROTO_ICMP:
			// ICMP checksum doesn't use a pseudo header so no need to update it.
			// bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum), orig_ip_dst, nat2_val->addr, 4);
			/* no break */
		default:
			eth_hdr = (void *)(long)skb->data;
			ip_header = (void *)(eth_hdr+1);

			if (((void*)(ip_header+1)) + sizeof(struct udphdr) > (void *)(long)skb->data_end) {
				CALICO_DEBUG_AT("Too short\n");
				goto deny;
			}
		};
		ip_header->daddr = nat2_val->addr;

		// Did a NAT, set up the reverse conntrack key accordingly.
		ct_rev_key.src_addr = nat2_val->addr;
		ct_rev_key.src_port = be16_to_host(nat2_val->port);
		ct_rev_key.dst_addr = orig_ip_src;
		ct_rev_key.dst_port = sport.port;
		ct_rev_key.protocol = ip_header->protocol;

		CALICO_DEBUG_AT("CT rev key src=%x dst=%x\n", ct_rev_key.src_addr , ct_rev_key.dst_addr);
		CALICO_DEBUG_AT("CT rev key sport=%x dport=%x\n", ct_rev_key.src_port, ct_rev_key.dst_port);
		ct_value.ct_type = CALICO_CT_TYPE_NAT;
		ct_value.data.ct_nat.src_addr = orig_ip_src;
		ct_value.data.ct_nat.src_port = host_to_be16(sport.port);
		ct_value.data.ct_nat.dst_addr = nat2_val->addr;
		ct_value.data.ct_nat.dst_port = nat2_val->port;
		ct_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;

		ct_rev_value.ct_type = CALICO_CT_TYPE_NAT;
		ct_rev_value.data.ct_nat.src_addr = orig_ip_dst;
		ct_rev_value.data.ct_nat.src_port = host_to_be16(dport.port);
		ct_rev_value.data.ct_nat.dst_addr = orig_ip_src;
		ct_rev_value.data.ct_nat.dst_port = host_to_be16(sport.port);
		ct_rev_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
		timer_end_time = bpf_ktime_get_ns();
	} else {
		// Did not do a DNAT, set up the reverse conntrack key accordingly.
		ct_rev_key.dst_addr = orig_ip_src;
		ct_rev_key.src_addr = orig_ip_dst;
		ct_rev_key.src_port = dport.port;
		ct_rev_key.dst_port = sport.port;
		ct_rev_key.protocol = ip_header->protocol;

		ct_value.ct_type = CALICO_CT_TYPE_ALLOW;
		ct_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
		ct_rev_value.ct_type = CALICO_CT_TYPE_ALLOW;
		ct_rev_value.flags |= (flags & CALICO_TC_HOST_EP) ? CALICO_CT_F_HOST_APPROVED : CALICO_CT_F_WORKLOAD_APPROVED;
	}

	// Check whether the traffic is to a local IP on this host or not.
	enum calico_policy_result norm_rc;

	if (flags & CALICO_TC_HOST_EP) {
		__be32 *ip = (flags & CALICO_TC_INGRESS) ? &ip_header->daddr : &ip_header->saddr;
		if (bpf_map_lookup_elem(&calico_local_ips, ip)) {
			// IP is local, apply normal policy.
			CALICO_DEBUG_AT("Local destination, using normal rules.\n");
			norm_rc = execute_policy_norm(ip_header, &sport, &dport, flags);
		} else {
			CALICO_DEBUG_AT("Remote destination, using apply-on-forward rules.\n");
			norm_rc = execute_policy_aof(ip_header, &sport, &dport, flags);
		}
	} else {
		CALICO_DEBUG_AT("Workload: applying normal policy.\n");
		norm_rc = execute_policy_norm(ip_header, &sport, &dport, flags);
	}


	switch (norm_rc) {
	case CALICO_POL_ALLOW:
		CALICO_DEBUG_AT("Match: Allowed by normal/apply-on-forward policy\n");
		reason = CALICO_REASON_POL;
		break;
	case CALICO_POL_DENY:
		CALICO_DEBUG_AT("Match: Explicitly denied by normal/apply-on-forward policy.\n");
		reason = CALICO_REASON_POL;
		goto deny;
	default:
		CALICO_DEBUG_AT("Match: Implicitly denied by normal/apply-on-forward policy.\n");
		reason = CALICO_REASON_POL;
		goto deny;
	}

	// If we get here, packet was allowed, record it in conntrack.

	bpf_map_update_elem(&calico_ct_map_v4, &ct_key, &ct_value, 0);
	bpf_map_update_elem(&calico_ct_map_v4, &ct_rev_key, &ct_rev_value, 0);

	// Try a short-circuit FIB lookup.
	struct calico_mac_sw_value *value;
	allow:

	if (((flags & CALICO_TC_HOST_EP) && (flags & CALICO_TC_INGRESS)) ||
			(!(flags & CALICO_TC_HOST_EP) && !(flags & CALICO_TC_INGRESS))) {
		if (CALICO_USE_LINUX_FIB) {
			CALICO_DEBUG_AT("Traffic is towards the host namespace, doing Linux FIB lookup\n");
			struct bpf_fib_lookup params = {};
			params.family = 2; // AF_INET
			params.l4_protocol = ip_header->protocol;
			params.sport = sport.port;
			params.dport = dport.port;
			params.tot_len = be16_to_host(ip_header->tot_len);
			params.ipv4_src = ip_header->saddr;
			params.ipv4_dst = ip_header->daddr;
			params.ifindex = skb->ingress_ifindex;

			rc =  bpf_fib_lookup(skb, &params, sizeof(params), 0);
			if (rc == 0) {
				CALICO_DEBUG_AT("FIB lookup succeeded\n");
				// Update the MACs.
				__builtin_memcpy(&eth_hdr->h_source, &params.smac, sizeof(eth_hdr->h_source));
				__builtin_memcpy(&eth_hdr->h_dest, &params.dmac, sizeof(eth_hdr->h_dest));

				// Redirect the packet.
				CALICO_DEBUG_AT("Got Linux FIB hit, redirecting to iface %d.\n",params.ifindex);
				rc = bpf_redirect(params.ifindex, 0);
			} else if (rc < 0) {
				CALICO_DEBUG_AT("FIB lookup failed (bad input): %d.\n", rc);
				rc = TC_ACT_UNSPEC;
			} else {
				CALICO_DEBUG_AT("FIB lookup failed (FIB problem): %d.\n", rc);
				rc = TC_ACT_UNSPEC;
			}
		} else {
			CALICO_DEBUG_AT("Traffic is towards the host namespace, doing Calico FIB lookup");
			value = bpf_map_lookup_elem(&calico_mac_sw_map, &ip_header->daddr);
			if (value) {
				// Update the MACs.
				__builtin_memcpy(&eth_hdr->h_source, &value->new_src, sizeof(eth_hdr->h_source));
				__builtin_memcpy(&eth_hdr->h_dest, &value->new_dst, sizeof(eth_hdr->h_dest));

				// Redirect the packet.
				CALICO_DEBUG_AT("Got Calico FIB hit, redirecting to iface %d.\n",value->dst_iface);
				uint32_t flags = 0;
				if (value->flags && CALICO_MAC_SW_FLAG_INGRESS) {
					CALICO_DEBUG_AT("Doing an ingress redirect.\n");
					flags |= BPF_F_INGRESS;
				}
				rc = bpf_redirect(value->dst_iface, flags);
			}
		}
	}
	allow_no_fib:
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




static CALICO_BPF_INLINE int redir(struct __sk_buff *skb) {
    if (skb->protocol != be16_to_host(ETH_P_IP)) {
        CALICO_DEBUG("Skipping protocol %x\n", skb->protocol);
        return TC_ACT_UNSPEC;
    }

    void *data_start = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data_start + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        CALICO_DEBUG("Too short\n");
        return TC_ACT_SHOT;
    }

    struct ethhdr *eth_hdr = data_start;
    struct iphdr *ip_header = (void *)(eth_hdr+1);

    // Look up the destination.
    struct calico_mac_sw_value *value = bpf_map_lookup_elem(&calico_mac_sw_map, &ip_header->daddr);
    if (!value) {
        CALICO_DEBUG("No match for dest addr %x\n", ip_header->daddr);
        return TC_ACT_UNSPEC;
    }

    // Update the MACs.
    __builtin_memcpy(&eth_hdr->h_source, &value->new_src, sizeof(eth_hdr->h_source));
    __builtin_memcpy(&eth_hdr->h_dest, &value->new_dst, sizeof(eth_hdr->h_dest));

    // Redirect the packet.
    CALICO_DEBUG("REDIR: Dest iface %d\n",value->dst_iface );
    uint32_t flags = 0;
    if (value->flags && CALICO_MAC_SW_FLAG_INGRESS) {
        flags |= BPF_F_INGRESS;
    }
    int rc = bpf_redirect(value->dst_iface, flags);
    CALICO_DEBUG("RC = %d\n", rc);
    return rc;
}

__attribute__((section("redirect")))
int tc_redirect(struct __sk_buff *skb) {
    return redir(skb);
}

static CALICO_BPF_INLINE int nat(struct __sk_buff *skb) {
    if (skb->protocol != be16_to_host(ETH_P_IP)) {
        CALICO_DEBUG("Skipping protocol %x\n", skb->protocol);
        return TC_ACT_UNSPEC;
    }

    void *data_start = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data_start + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        CALICO_DEBUG("Too short\n");
        return TC_ACT_SHOT;
    }

    struct ethhdr *eth_hdr = data_start;
    struct iphdr *ip_header = (void *)(eth_hdr+1);

    uint32_t new_src = ip_header->saddr;
    bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &new_src, 4, BPF_F_RECOMPUTE_CSUM);

    return TC_ACT_UNSPEC;
}

__attribute__((section("nat")))
int tc_nat(struct __sk_buff *skb) {
    return nat(skb);
}

__attribute__((section("allow_all")))
int tc_allow_all(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}

__attribute__((section("log_and_allow")))
int tc_log_and_allow(struct __sk_buff *skb)
{
	printk("log-and-allow proto=%d\n", skb->protocol);
    return TC_ACT_UNSPEC;
}

__attribute__((section("drop_all")))
int tc_drop_all(struct __sk_buff *skb)
{
	return TC_ACT_SHOT;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
