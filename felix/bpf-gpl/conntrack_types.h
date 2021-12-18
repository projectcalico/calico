// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_CONNTRACK_TYPES_H__
#define __CALI_CONNTRACK_TYPES_H__

// Connection tracking.

struct calico_ct_key {
	__u32 protocol;
	__be32 addr_a, addr_b; // NBO
	__u16 port_a, port_b; // HBO
};

enum cali_ct_type {
	CALI_CT_TYPE_NORMAL	= 0x00, /* Non-NATted entry. */
	CALI_CT_TYPE_NAT_FWD	= 0x01, /* Forward entry for a DNATted flow, keyed on orig src/dst.
					 * Points to the reverse entry.
					 */
	CALI_CT_TYPE_NAT_REV	= 0x02, /* "Reverse" entry for a NATted flow, contains NAT +
					 * tracking information.
					 */
};

#define CALI_CT_FLAG_NAT_OUT	0x01
#define CALI_CT_FLAG_DSR_FWD	0x02 /* marks entry into the tunnel on the fwd node when dsr */
#define CALI_CT_FLAG_NP_FWD	0x04 /* marks entry into the tunnel on the fwd node */
#define CALI_CT_FLAG_SKIP_FIB	0x08 /* marks traffic that should pass through host IP stack */
#define CALI_CT_FLAG_RES_0x10	0x10 /* reserved */
#define CALI_CT_FLAG_RES_0x20	0x20 /* reserved */
#define CALI_CT_FLAG_EXT_LOCAL	0x40 /* marks traffic from external client to a local serice */
#define CALI_CT_FLAG_VIA_NAT_IF	0x80 /* marks connection first seen on the service veth */

struct calico_ct_leg {
	__u32 seqno;

	__u32 syn_seen:1;
	__u32 ack_seen:1;
	__u32 fin_seen:1;
	__u32 rst_seen:1;

	__u32 whitelisted:1;

	__u32 opener:1;

	__u32 ifindex; /* For a CT leg where packets ingress through an interface towards
			* the host, this is the ingress interface index.  For a CT leg
			* where packets originate _from_ the host, it's CT_INVALID_IFINDEX
			* (0).
			*/
};

#define CT_INVALID_IFINDEX	0
struct calico_ct_value {
	__u64 created;
	__u64 last_seen; // 8
	__u8 type;		 // 16
	__u8 flags;

	// Important to use explicit padding, otherwise the compiler can decide
	// not to zero the padding bytes, which upsets the verifier.  Worse than
	// that, debug logging often prevents such optimisation resulting in
	// failures when debug logging is compiled out only :-).
	__u8 pad0[5];
	__u8 flags2;
	union {
		// CALI_CT_TYPE_NORMAL and CALI_CT_TYPE_NAT_REV.
		struct {
			struct calico_ct_leg a_to_b; // 24
			struct calico_ct_leg b_to_a; // 36

			// CALI_CT_TYPE_NAT_REV
			__u32 orig_ip;                     // 44
			__u16 orig_port;                   // 48
			__u16 orig_sport;                  // 50
			__u32 tun_ip;                      // 52
			__u32 pad3;                        // 56
		};

		// CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
		struct {
			struct calico_ct_key nat_rev_key;  // 24
			__u16 nat_sport;
			__u8 pad2[6];
		};
	};
};

#define ct_value_set_flags(v, f) do {		\
	(v)->flags |= ((f) & 0xff);		\
	(v)->flags2 |= (((f) >> 8) & 0xff);	\
} while(0)

#define ct_value_get_flags(v) ({			\
	__u16 ret = (v)->flags | ((v)->flags2 << 8);	\
							\
	ret;						\
})

struct ct_lookup_ctx {
	__u8 proto;
	__be32 src;
	__be32 dst;
	__u16 sport;
	__u16 dport;
	struct tcphdr *tcp;
};

struct ct_create_ctx {
	struct __sk_buff *skb;
	__u8 proto;
	__be32 src;
	__be32 orig_dst;
	__be32 dst;
	__u16 sport;
	__u16 dport;
	__u16 orig_dport;
	__u16 orig_sport;
	struct tcphdr *tcp;
	__be32 tun_ip; /* is set when the packet arrive through the NP tunnel.
			* It is also set on the first node when we create the
			* initial CT entry for the tunneled traffic. */
	__u16 flags;
	enum cali_ct_type type;
	bool allow_return;
};

CALI_MAP(cali_v4_ct, 2,
		BPF_MAP_TYPE_HASH,
		struct calico_ct_key, struct calico_ct_value,
		512000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

enum calico_ct_result_type {
	/* CALI_CT_NEW means that the packet is not part of a known conntrack flow.
	 * TCP SYN packets are always treated as NEW so they always go through policy. */
	CALI_CT_NEW = 0,
	/* CALI_CT_MID_FLOW_MISS indicates that the packet is known to be of a type that
	 * cannot be the start of a flow but it also has no matching conntrack entry.  For
	 * example, a TCP packet without SYN set. */
	CALI_CT_MID_FLOW_MISS = 1,
	/* CALI_CT_ESTABLISHED indicates the packet is part of a known flow, approved at "this"
	 * side.  I.e. it's safe to let this packet through _this_ program.  If a packet is
	 * ESTABLISHED but not ESTABLISHED_BYPASS then it has only been approved by _this_
	 * program, but downstream programs still need to have their say. For example, if this
	 * is a workload egress program then it implements egress policy for one workload. If
	 * that workload communicates with another workload on the same host then the packet
	 * needs to be approved by the ingress policy program attached to the other workload. */
	CALI_CT_ESTABLISHED = 2,
	/* CALI_CT_ESTABLISHED_BYPASS indicates the packet is part of a known flow and *both*
	 * legs of the conntrack entry have been approved.  Hence it is safe to set the bypass
	 * mark bit on the traffic so that any downstream BPF programs let the packet through
	 * automatically. */
	CALI_CT_ESTABLISHED_BYPASS = 3,
	/* CALI_CT_ESTABLISHED_SNAT means the packet is a response packet on a NATted flow;
	 * hence the packet needs to be SNATted. The new src IP and port are returned in
	 * result.nat_ip and result.nat_port. */
	CALI_CT_ESTABLISHED_SNAT = 4,
	/* CALI_CT_ESTABLISHED_DNAT means the packet is a request packet on a NATted flow;
	 * hence the packet needs to be DNATted. The new dst IP and port are returned in
	 * result.nat_ip and result.nat_port. */
	CALI_CT_ESTABLISHED_DNAT = 5,
	/* CALI_CT_INVALID is returned for packets that cannot be parsed (e.g. invalid ICMP response)
	 * or for packet that have a conntrack entry that is only approved by the other leg
	 * (indicating that policy on this leg failed to allow the packet). */
	CALI_CT_INVALID = 6,
};

#define CALI_CT_RELATED         0x100
#define CALI_CT_RPF_FAILED      0x200
#define CALI_CT_TUN_SRC_CHANGED 0x400
#define CALI_CT_RESERVED_800	0x800
#define CALI_CT_SYN		0x1000

#define ct_result_rc(rc)		((rc) & 0xff)
#define ct_result_flags(rc)		((rc) & ~0xff)
#define ct_result_set_rc(val, rc)	((val) = ct_result_flags(val) | (rc))
#define ct_result_set_flag(val, flags)	((val) |= (flags))

#define ct_result_is_related(rc)	((rc) & CALI_CT_RELATED)
#define ct_result_rpf_failed(rc)	((rc) & CALI_CT_RPF_FAILED)
#define ct_result_tun_src_changed(rc)	((rc) & CALI_CT_TUN_SRC_CHANGED)
#define ct_result_is_syn(rc)		((rc) & CALI_CT_SYN)

struct calico_ct_result {
	__s16 rc;
	__u16 flags;
	__be32 nat_ip;
	__u16 nat_port;
	__u16 nat_sport;
	__be32 tun_ip;
	__u32 ifindex_fwd; /* if set, the ifindex where the packet should be forwarded */
	__u32 ifindex_created; /* For a CT state that was created by a packet ingressing
				* through an interface towards the host, this is the
				* ingress interface index.  For a CT state created by a
				* packet _from_ the host, it's CT_INVALID_IFINDEX (0).
				*/
};

#endif /* __CALI_CONNTRAC_TYPESK_H__ */
