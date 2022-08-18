// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_TYPES_H__
#define __CALI_BPF_TYPES_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include "bpf.h"
#include "arp.h"
#include "conntrack_types.h"
#include "nat_types.h"
#include "reasons.h"
#include "counters.h"

#define MAX_RULE_IDS    32

// struct cali_tc_state holds state that is passed between the BPF programs.
// WARNING: must be kept in sync with
// - the definitions in bpf/polprog/pol_prog_builder.go.
// - the Go version of the struct in bpf/state/map.go
struct cali_tc_state {
	/* Initial IP read from the packet, updated to host's IP when doing NAT encap/ICMP error.
	 * updated when doing CALI_CT_ESTABLISHED_SNAT handling. Used for FIB lookup. */
	__be32 ip_src;
	/* Initial IP read from packet. Updated when doing encap and ICMP errors or CALI_CT_ESTABLISHED_DNAT.
	 * If connect-time load balancing is enabled, this will be the post-NAT IP because the connect-time
	 * load balancer gets in before TC. */
	__be32 ip_dst;
	/* Set when invoking the policy program; if no NAT, ip_dst; otherwise, the pre-DNAT IP.  If the connect
	 * time load balancer is enabled, this may be different from ip_dst. */
	__be32 pre_nat_ip_dst;
	/* If no NAT, ip_dst.  Otherwise the NAT dest that we look up from the NAT maps or the conntrack entry
	 * for CALI_CT_ESTABLISHED_DNAT. */
	__be32 post_nat_ip_dst;
	/* For packets that arrived over our VXLAN tunnel, the source IP of the tunnel packet.
	 * Zeroed out when we decide to respond with an ICMP error.
	 * Also used to stash the ICMP MTU when calling the ICMP response program. */
	__be32 tun_ip;
	/* Return code from the policy program CALI_POL_DENY/ALLOW etc. */
	__s32 pol_rc;
	/* Source port of the packet; updated on the CALI_CT_ESTABLISHED_SNAT path or when doing encap.
	 * zeroed out on the ICMP response path. */
	__u16 sport;
	union
	{
		/* dport is the destination port of the packet; it may be pre or post NAT */
		__u16 dport;
		struct
		{
			__u8 icmp_type;
			__u8 icmp_code;
		};
	};
	/* Pre-NAT dest port; set similarly to pre_nat_ip_dst. */
	__u16 pre_nat_dport;
	/* Post-NAT dest port; set similarly to post_nat_ip_dst. */
	__u16 post_nat_dport;
	/* Packet IP proto; updated to UDP when we encap. */
	__u8 ip_proto;
	/* Flags from enum cali_state_flags. */
	__u8 __pad;
	/* Packet size filled from iphdr->tot_len in tc_state_fill_from_iphdr(). */
	__be16 ip_size;
	/* Count of rules that were hit while processing policy. */
	__u32 rules_hit;
	/* Record of the rule IDs of the rules that were hit. */
	__u64 rule_ids[MAX_RULE_IDS];

	/* Result of the conntrack lookup. */
	struct calico_ct_result ct_result; /* 28 bytes */

	/* Result of the NAT calculation.  Zeroed if there is no DNAT. */
	struct calico_nat_dest nat_dest; /* 8 bytes */
	__u64 prog_start_time;
	__u64 flags;
};

enum cali_state_flags {
	/* CALI_ST_NAT_OUTGOING is set if this packet is from a NAT-outgoing IP pool and is leaving the
	 * Calico network. Such packets are dropped through to iptables for SNAT. */
	CALI_ST_NAT_OUTGOING	  = 0x01,
	/* CALI_ST_SKIP_FIB is set if the BPF FIB lookup should be skipped for this packet (for example, to
	 * allow for the kernel RPF check to run. */
	CALI_ST_SKIP_FIB	  = 0x02,
	/* CALI_ST_DEST_IS_HOST is set if the packet is towards the host namespace and the destination
	 * belongs to the host. */
	CALI_ST_DEST_IS_HOST	  = 0x04,
	/* CALI_ST_SRC_IS_HOST is set if the packet is heading away from the host namespace and the source
	 * belongs to the host. */
	CALI_ST_SRC_IS_HOST	  = 0x08,
	/* CALI_ST_SUPPRESS_CT_STATE prevents the creation of any new CT state. */
	CALI_ST_SUPPRESS_CT_STATE = 0x10,
	/* CALI_ST_SKIP_POLICY is set when the policy program is skipped. */
	CALI_ST_SKIP_POLICY	  = 0x20,
	/* CALI_ST_HOST_PSNAT is set when we are resolving host source port collision. */
	CALI_ST_HOST_PSNAT	  = 0x40,
	/* CALI_ST_CT_NP_LOOP tells CT when creating an entry that we are
	 * turnign this packet around from a nodeport to a local pod. */
	CALI_ST_CT_NP_LOOP	  = 0x80,
	/* CALI_ST_CT_NP_REMOTE is set when host is accessing a remote nodeport. */
	CALI_ST_CT_NP_REMOTE	  = 0x100,
};

struct fwd {
	int res;
	__u32 mark;
	enum calico_reason reason;
#if CALI_FIB_ENABLED
	__u32 fib_flags;
	bool fib;
#endif
};

struct cali_tc_ctx {
  struct __sk_buff *skb;
  struct xdp_md *xdp;

  /* Our single copies of the data start/end pointers loaded from the skb. */
  void *data_start;
  void *data_end;
  void *ip_header;
  void *nh;
  long ipheader_len;

  struct cali_tc_state *state;
  struct calico_nat_dest *nat_dest;
  struct arp_key arpk;
  struct fwd fwd;
  counters_t *counters;
};

static CALI_BPF_INLINE struct iphdr* ip_hdr(struct cali_tc_ctx *ctx)
{
	return (struct iphdr *)ctx->ip_header;
}

static CALI_BPF_INLINE struct ipv6hdr* ipv6_hdr(struct cali_tc_ctx *ctx)
{
	return (struct ipv6hdr *)ctx->ip_header;
}

static CALI_BPF_INLINE struct ethhdr* eth_hdr(struct cali_tc_ctx *ctx)
{
	return (struct ethhdr *)ctx->data_start;
}

static CALI_BPF_INLINE struct tcphdr* tcp_hdr(struct cali_tc_ctx *ctx)
{
	return (struct tcphdr *)ctx->nh;
}

static CALI_BPF_INLINE struct udphdr* udp_hdr(struct cali_tc_ctx *ctx)
{
	return (struct udphdr *)ctx->nh;
}

static CALI_BPF_INLINE struct icmphdr* icmp_hdr(struct cali_tc_ctx *ctx)
{
	return (struct icmphdr *)ctx->nh;
}

static CALI_BPF_INLINE struct ipv6_opt_hdr* ipv6ext_hdr(struct cali_tc_ctx *ctx)
{
	return (struct ipv6_opt_hdr *)ctx->nh;
}

#endif /* __CALI_BPF_TYPES_H__ */
