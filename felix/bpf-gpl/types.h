// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_TYPES_H__
#define __CALI_BPF_TYPES_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#ifdef IPVER6
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#else
#include <linux/ip.h>
#include <linux/icmp.h>
#endif
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include "bpf.h"
#include "arp.h"
#include "conntrack_types.h"
#include "nat_types.h"
#include "reasons.h"

#define IPV4_UDP_SIZE		(sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_IPV4_UDP_SIZE	(sizeof(struct ethhdr) + IPV4_UDP_SIZE)

#define ETH_SIZE (sizeof(struct ethhdr))
#ifdef IPVER6
#define IP_SIZE (sizeof(struct ipv6hdr))
#define ICMP_SIZE (sizeof(struct icmp6hdr))
#else
#define IP_SIZE (sizeof(struct iphdr))
#define ICMP_SIZE (sizeof(struct icmphdr))
#endif
#define UDP_SIZE (sizeof(struct udphdr))
#define TCP_SIZE (sizeof(struct tcphdr))

#define MAX_RULE_IDS    32

// struct cali_tc_state holds state that is passed between the BPF programs.
// WARNING: must be kept in sync with
// - the definitions in bpf/polprog/pol_prog_builder.go.
// - the Go version of the struct in bpf/state/map.go
struct cali_tc_state {
	/* Initial IP read from the packet, updated to host's IP when doing NAT encap/ICMP error.
	 * updated when doing CALI_CT_ESTABLISHED_SNAT handling. Used for FIB lookup. */
	DECLARE_IP_ADDR(ip_src);
	/* Initial IP read from packet. Updated when doing encap and ICMP errors or CALI_CT_ESTABLISHED_DNAT.
	 * If connect-time load balancing is enabled, this will be the post-NAT IP because the connect-time
	 * load balancer gets in before TC. */
	DECLARE_IP_ADDR(ip_dst);
	/* Set when invoking the policy program; if no NAT, ip_dst; otherwise, the pre-DNAT IP.  If the connect
	 * time load balancer is enabled, this may be different from ip_dst. */
	DECLARE_IP_ADDR(pre_nat_ip_dst);
	/* If no NAT, ip_dst.  Otherwise the NAT dest that we look up from the NAT maps or the conntrack entry
	 * for CALI_CT_ESTABLISHED_DNAT. */
	DECLARE_IP_ADDR(post_nat_ip_dst);
	union {
		/* For packets that arrived over our VXLAN tunnel, the source IP of the tunnel packet.
		 * Zeroed out when we decide to respond with an ICMP error.
		 * Also used to stash the ICMP MTU when calling the ICMP response program. */
		DECLARE_IP_ADDR(tun_ip);
		__u32 icmp_un;
	};
	__u16 ihl;
	__u16 unused;
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
			/* Only used to pass type/code to the program that generates and
			 * send an ICMP error response and to the policy program.
			 */
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
#ifndef IPVER6
	__u8 __pad_ipv4[48];
#endif
};

struct pkt_scratch {
	__u8 l4[24]; /* 20 bytes to fit udp, icmp, tcp w/o options and 24 to make 8-aligned */
	struct ct_create_ctx ct_ctx_nat;
	struct calico_ct_key ct_key;
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
	 * turning this packet around from a nodeport to a local pod. */
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
#if !CALI_F_XDP
  struct __sk_buff *skb;
#else
  struct xdp_md *xdp;
#endif

  /* Our single copies of the data start/end pointers loaded from the skb. */
  void *data_start;
  void *data_end;
  void *ip_header;
  long ipheader_len;
  void *nh;

  struct cali_tc_state *state;
#if !CALI_F_XDP
  const volatile struct cali_tc_globals *globals;
#else
  const volatile struct cali_xdp_globals *xdp_globals; /* XXX we must split the state between tc/xdp */
#endif
  struct calico_nat_dest *nat_dest;
  struct fwd fwd;
  void *counters;
  struct pkt_scratch *scratch;
};

#define DECLARE_TC_CTX(NAME, ...)						\
	struct cali_tc_ctx NAME = ({						\
			struct cali_tc_state *state = state_get();		\
			if (!state) {						\
				CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "State map lookup failed: DROP\n");	\
				bpf_exit(TC_ACT_SHOT);				\
			}							\
			void * counters = counters_get(skb->ifindex);		\
			if (!counters) {					\
				CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "no counters: DROP\n");		\
				bpf_exit(TC_ACT_SHOT);				\
			}							\
			struct cali_tc_globals *gl = state_get_globals_tc();	\
			if (!gl) {						\
				CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "no globals: DROP\n");		\
				bpf_exit(TC_ACT_SHOT);				\
			}							\
			struct pkt_scratch *scratch = (void *)(gl->__scratch); 	\
			struct cali_tc_ctx x = {				\
				.state = state,					\
				.counters = counters,				\
				.globals = gl,					\
				.scratch = scratch,				\
				.nh = &scratch->l4,				\
				__VA_ARGS__					\
			};							\
			if (x.ipheader_len == 0) {				\
				x.ipheader_len = state->ihl;			\
			}							\
										\
			x;							\
	})

#define STATE (ctx->state)

#define fib_params(x) ((struct bpf_fib_lookup *)((x)->scratch))

#ifdef IPVER6
static CALI_BPF_INLINE struct ipv6hdr* ip_hdr(struct cali_tc_ctx *ctx)
{
	return (struct ipv6hdr *)ctx->ip_header;
}

static CALI_BPF_INLINE struct icmp6hdr* icmp_hdr(struct cali_tc_ctx *ctx)
{
	return (struct icmp6hdr *)ctx->nh;
}

#define ip_hdr_set_ip(ctx, field, ip)	do {					\
	struct in6_addr *addr = &(ip_hdr(ctx)->field);				\
	addr->in6_u.u6_addr32[0] = ip.a;					\
	addr->in6_u.u6_addr32[1] = ip.b;					\
	addr->in6_u.u6_addr32[2] = ip.c;					\
	addr->in6_u.u6_addr32[3] = ip.d;					\
} while(0)

#else

static CALI_BPF_INLINE struct iphdr* ip_hdr(struct cali_tc_ctx *ctx)
{
	return (struct iphdr *)ctx->ip_header;
}

#define ip_hdr_set_ip(ctx, field, ip)	do {					\
	ip_hdr(ctx)->field = ip;						\
} while (0)

static CALI_BPF_INLINE struct icmphdr* icmp_hdr(struct cali_tc_ctx *ctx)
{
	return (struct icmphdr *)ctx->nh;
}

#endif

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

static CALI_BPF_INLINE __u32 ctx_ifindex(struct cali_tc_ctx *ctx)
{
#if CALI_F_XDP
	return ctx->xdp->ingress_ifindex;
#else
	return ctx->skb->ifindex;
#endif
}

static CALI_BPF_INLINE int l4_hdr_len(struct cali_tc_ctx *ctx)
{
	switch (ctx->state->ip_proto) {
	case IPPROTO_TCP:
		return TCP_SIZE;
	case IPPROTO_UDP:
		return UDP_SIZE;
	case IPPROTO_ICMP:
		ICMP_SIZE;
	}

	return 0;
}

#define IP_VOID 0
#define IP_EQ(ip1, ip2) ((ip1) == (ip2))
#define IP_SET(var, val) ((var) = (val))


#endif /* __CALI_BPF_TYPES_H__ */
