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

#ifndef __CALI_CONNTRACK_H__
#define __CALI_CONNTRACK_H__

#include <linux/in.h>
#include "nat.h"
#include "bpf.h"
#include "icmp.h"

// Connection tracking.

struct calico_ct_key {
	uint32_t protocol;
	__be32 addr_a, addr_b; // NBO
	uint16_t port_a, port_b; // HBO
};

#define src_lt_dest(ip_src, ip_dst, sport, dport) \
	((ip_src) < (ip_dst)) || (((ip_src) == (ip_dst)) && (sport) < (dport))

#define __ct_make_key(proto, ipa, ipb, porta, portb) 		\
		(struct calico_ct_key) {			\
			.protocol = proto,			\
			.addr_a = ipa, .port_a = porta,		\
			.addr_b = ipb, .port_b = portb,		\
		}

#define ct_make_key(sltd, p, ipa, ipb, pta, ptb) ({						\
	struct calico_ct_key k;									\
	k = sltd ? __ct_make_key(p, ipa, ipb, pta, ptb) : __ct_make_key(p, ipb, ipa, ptb, pta);	\
	dump_ct_key(&k);									\
	k;											\
})

enum cali_ct_type {
	CALI_CT_TYPE_NORMAL	= 0x00, /* Non-NATted entry. */
	CALI_CT_TYPE_NAT_FWD	= 0x01, /* Forward entry for a DNATted flow, keyed on orig src/dst.
					 * Points to the reverse entry.
					 */
	CALI_CT_TYPE_NAT_REV	= 0x02, /* "Reverse" entry for a NATted flow, contains NAT +
					 * tracking information.
					 */
};

#define CALI_CT_FLAG_NAT_OUT	(1 << 0)
#define CALI_CT_FLAG_DSR_FWD	(1 << 1) /* marks entry into the tunnel on the fwd node when dsr */
#define CALI_CT_FLAG_NP_FWD	(1 << 2) /* marks entry into the tunnel on the fwd node */
#define CALI_CT_FLAG_SKIP_FIB	(1 << 3) /* marks traffic that should pass through host IP stack */

#define ct_result_np_node(res)		((res).flags & CALI_CT_FLAG_NP_FWD)

struct calico_ct_leg {
	__u32 seqno;

	__u32 syn_seen:1;
	__u32 ack_seen:1;
	__u32 fin_seen:1;
	__u32 rst_seen:1;

	__u32 whitelisted:1;

	__u32 opener:1;

	__u32 ifindex; /* where the packet entered the system from */
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
	__u8 pad0[6];
	union {
		// CALI_CT_TYPE_NORMAL and CALI_CT_TYPE_NAT_REV.
		struct {
			struct calico_ct_leg a_to_b; // 24
			struct calico_ct_leg b_to_a; // 36

			// CALI_CT_TYPE_NAT_REV
			__u32 orig_ip;                     // 44
			__u16 orig_port;                   // 48
			__u8 pad1[2];                      // 50
			__u32 tun_ip;                      // 52
			__u32 pad3;                        // 56
		};

		// CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
		struct {
			struct calico_ct_key nat_rev_key;  // 24
			__u8 pad2[8];
		};
	};
};

#define CT_CREATE_NORMAL	0
#define CT_CREATE_NAT		1
#define CT_CREATE_NAT_FWD	2

struct ct_ctx {
	struct __sk_buff *skb;
	__u8 proto;
	__be32 src;
	__be32 orig_dst;
	__be32 dst;
	__u16 sport;
	__u16 dport;
	__u16 orig_dport;
	struct tcphdr *tcp;
	__be32 tun_ip; /* is set when the packet arrive through the NP tunnel.
			* It is also set on the first node when we create the
			* initial CT entry for the tunneled traffic. */
	__u8 flags;
};

CALI_MAP(cali_v4_ct, 2,
		BPF_MAP_TYPE_HASH,
		struct calico_ct_key, struct calico_ct_value,
		512000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE void dump_ct_key(struct calico_ct_key *k)
{
	CALI_VERB("CT-ALL   key A=%x:%d proto=%d\n", be32_to_host(k->addr_a), k->port_a, (int)k->protocol);
	CALI_VERB("CT-ALL   key B=%x:%d size=%d\n", be32_to_host(k->addr_b), k->port_b, (int)sizeof(struct calico_ct_key));
}

static CALI_BPF_INLINE int calico_ct_v4_create_tracking(struct ct_ctx *ctx,
							struct calico_ct_key *k,
							enum cali_ct_type type,
							int nat)
{
	__be32 ip_src = ctx->src;
	__be32 ip_dst = ctx->dst;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->dport;
	__be32 orig_dst = ctx->orig_dst;
	__u16 orig_dport = ctx->orig_dport;
	int err = 0;


	__be32 seq = 0;
	bool syn = false;
	__u64 now;

	if (ctx->tcp) {
		seq = ctx->tcp->seq;
		syn = ctx->tcp->syn;
	}

	CALI_DEBUG("CT-ALL packet mark is: 0x%x\n", ctx->skb->mark);
	if ((ctx->skb->mark & CALI_SKB_MARK_SEEN_MASK) == CALI_SKB_MARK_SEEN) {
		/* Packet already marked as being from another workload, which will
		 * have created a conntrack entry.  Look that one up instead of
		 * creating one.
		 */
		CALI_DEBUG("CT-ALL Asked to create entry but packet is marked as "
				"from another endpoint, doing lookup\n");
		bool srcLTDest = src_lt_dest(ip_src, ip_dst, sport, dport);
		*k = ct_make_key(srcLTDest, ctx->proto, ip_src, ip_dst, sport, dport);
		struct calico_ct_value *ct_value = cali_v4_ct_lookup_elem(k);
		if (!ct_value) {
			CALI_VERB("CT Packet marked as from workload but got a conntrack miss!\n");
			goto create;
		}
		CALI_VERB("CT Found expected entry, updating...\n");
		if (srcLTDest) {
			CALI_VERB("CT-ALL update src_to_dst A->B\n");
			ct_value->a_to_b.seqno = seq;
			ct_value->a_to_b.syn_seen = syn;
			if (CALI_F_TO_HOST) {
				ct_value->a_to_b.whitelisted = 1;
			} else {
				ct_value->b_to_a.whitelisted = 1;
			}
		} else  {
			CALI_VERB("CT-ALL update src_to_dst B->A\n");
			ct_value->b_to_a.seqno = seq;
			ct_value->b_to_a.syn_seen = syn;
			if (CALI_F_TO_HOST) {
				ct_value->b_to_a.whitelisted = 1;
			} else {
				ct_value->a_to_b.whitelisted = 1;
			}
		}

		return 0;
	}

create:
	now = bpf_ktime_get_ns();
	CALI_DEBUG("CT-ALL Creating tracking entry type %d at %llu.\n", type, now);

	struct calico_ct_value ct_value = {
		.created=now,
		.last_seen=now,
		.type = type,
		.orig_ip = orig_dst,
		.orig_port = orig_dport,
	};

	ct_value.flags = ctx->flags;
	CALI_DEBUG("CT-ALL tracking entry flags 0x%x\n", ct_value.flags);

	if (type == CALI_CT_TYPE_NAT_REV && ctx->tun_ip) {
		if (ctx->flags & CALI_CT_FLAG_NP_FWD) {
			CALI_DEBUG("CT-ALL nat tunneled to %x\n", be32_to_host(ctx->tun_ip));
		} else {
			struct cali_rt *rt = cali_rt_lookup(ctx->tun_ip);
			if (!rt || !cali_rt_is_host(rt)) {
				CALI_DEBUG("CT-ALL nat tunnel IP not a host %x\n", be32_to_host(ctx->tun_ip));
				err = -1;
				goto out;
			}
			CALI_DEBUG("CT-ALL nat tunneled from %x\n", be32_to_host(ctx->tun_ip));
		}
		ct_value.tun_ip = ctx->tun_ip;
	}

	struct calico_ct_leg *src_to_dst, *dst_to_src;
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);

	if (srcLTDest) {
		*k = (struct calico_ct_key) {
			.protocol = ctx->proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		CALI_VERB("CT-ALL src_to_dst A->B\n");
		src_to_dst = &ct_value.a_to_b;
		dst_to_src = &ct_value.b_to_a;
	} else  {
		*k = (struct calico_ct_key) {
			.protocol = ctx->proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		CALI_VERB("CT-ALL src_to_dst B->A\n");
		src_to_dst = &ct_value.b_to_a;
		dst_to_src = &ct_value.a_to_b;
	}

	dump_ct_key(k);

	__u32 ifindex = skb_ingress_ifindex(ctx->skb);

	src_to_dst->seqno = seq;
	src_to_dst->syn_seen = syn;
	src_to_dst->opener = 1;
	src_to_dst->ifindex = ifindex;
	CALI_DEBUG("NEW src_to_dst->ifindex %d\n", src_to_dst->ifindex);
	dst_to_src->ifindex = CT_INVALID_IFINDEX;

	if (CALI_F_FROM_WEP) {
		/* src is the from the WEP, policy whitelisted this side */
		src_to_dst->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted source side - from WEP\n");
	} else if (CALI_F_FROM_HEP) {
		/* src is the from the HEP, policy whitelisted this side */
		src_to_dst->whitelisted = 1;

		if (nat == CT_CREATE_NAT_FWD) {
			/* When we do NAT and forward through the tunnel, we go through
			 * a single policy, what we forward we also accept back,
			 * whitelist both sides.
			 */
			dst_to_src->whitelisted = 1;
		}
		CALI_DEBUG("CT-ALL Whitelisted source side - from HEP tun fwd=%d\n",
				nat == CT_CREATE_NAT_FWD);
	} else if (CALI_F_FROM_HOST) {
		/* dst is to the EP, policy whitelisted this side */
		dst_to_src->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted dest side - to EP\n");
	}

	err = cali_v4_ct_update_elem(k, &ct_value, 0);

out:
	CALI_VERB("CT-ALL Create result: %d.\n", err);
	return err;
}

static CALI_BPF_INLINE int calico_ct_v4_create_nat_fwd(struct ct_ctx *ctx,
						       struct calico_ct_key *rk)
{
	__u8 ip_proto = ctx->proto;
	__be32 ip_src = ctx->src;
	__be32 ip_dst = ctx->orig_dst;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->orig_dport;

	__u64 now = bpf_ktime_get_ns();

	CALI_DEBUG("CT-%d Creating FWD entry at %llu.\n", ip_proto, now);
	struct calico_ct_value ct_value = {
		.type = CALI_CT_TYPE_NAT_FWD,
		.last_seen = now,
		.created = now,
	};

	struct calico_ct_key k;

	if ((ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport)) {
		k = (struct calico_ct_key) {
			.protocol = ip_proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
	} else  {
		k = (struct calico_ct_key) {
			.protocol = ip_proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
	}

	dump_ct_key(&k);
	ct_value.nat_rev_key = *rk;
	int err = cali_v4_ct_update_elem(&k, &ct_value, 0);
	CALI_VERB("CT-%d Create result: %d.\n", ip_proto, err);
	return err;
}

static CALI_BPF_INLINE int calico_ct_v4_create(struct ct_ctx *ctx)
{
	struct calico_ct_key k;

	return calico_ct_v4_create_tracking(ctx, &k, CALI_CT_TYPE_NORMAL, CT_CREATE_NORMAL);
}

static CALI_BPF_INLINE int calico_ct_v4_create_nat(struct ct_ctx *ctx, int nat)
{
	struct calico_ct_key k;
	int err;

	err = calico_ct_v4_create_tracking(ctx, &k, CALI_CT_TYPE_NAT_REV, nat);
	if (!err) {
		err = calico_ct_v4_create_nat_fwd(ctx, &k);
		if (err) {
			/* XXX we should clean up the tracking entry */
		}
	}

	return err;
}

enum calico_ct_result_type {
	CALI_CT_NEW,
	CALI_CT_ESTABLISHED,
	CALI_CT_ESTABLISHED_BYPASS,
	CALI_CT_ESTABLISHED_SNAT,
	CALI_CT_ESTABLISHED_DNAT,
	CALI_CT_INVALID,
};

#define CALI_CT_RELATED		(1 << 8)
#define CALI_CT_RPF_FAILED	(1 << 9)
#define CALI_CT_TUN_SRC_CHANGED	(1 << 10)

#define ct_result_rc(rc)		((rc) & 0xff)
#define ct_result_flags(rc)		((rc) & ~0xff)
#define ct_result_set_rc(val, rc)	((val) = ct_result_flags(val) | (rc))
#define ct_result_set_flag(val, flags)	((val) |= (flags))

#define ct_result_is_related(rc)	((rc) & CALI_CT_RELATED)
#define ct_result_rpf_failed(rc)	((rc) & CALI_CT_RPF_FAILED)
#define ct_result_tun_src_changed(rc)	((rc) & CALI_CT_TUN_SRC_CHANGED)

struct calico_ct_result {
	__s16 rc;
	__u16 flags;
	__be32 nat_ip;
	__u32 nat_port;
	__be32 tun_ip;
	__u32 ifindex_fwd; /* if set, the ifindex where the packet should be forwarded */
};

/* skb_is_icmp_err_unpack fills in ctx, but only what needs to be changed. For instance, keeps the
 * cxt->skb or ctx->tun_ip. It returns true if the original packet is an icmp error and all
 * checks went well.
 */
static CALI_BPF_INLINE bool skb_is_icmp_err_unpack(struct __sk_buff *skb, struct ct_ctx *ctx)
{
	struct iphdr *ip;
	struct icmphdr *icmp;

	if (!icmp_skb_get_hdr(skb, &icmp)) {
		CALI_DEBUG("CT-ICMP: failed to get inner IP\n");
		return false;
	}

	if (!icmp_type_is_err(icmp->type)) {
		CALI_DEBUG("CT-ICMP: type %d not an error\n", icmp->type);
		return false;
	}

	ip = (struct iphdr *)(icmp + 1); /* skip to inner ip */
	CALI_DEBUG("CT-ICMP: proto %d\n", ip->protocol);

	ctx->proto = ip->protocol;
	ctx->src = ip->saddr;
	ctx->dst = ip->daddr;

	switch (ip->protocol) {
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
			ctx->sport = be16_to_host(tcp->source);
			ctx->dport = be16_to_host(tcp->dest);
			ctx->tcp = tcp;
		}
		break;
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip + 1);
			ctx->sport = be16_to_host(udp->source);
			ctx->dport = be16_to_host(udp->dest);
		}
		break;
	};

	return true;
}

static CALI_BPF_INLINE void calico_ct_v4_tcp_delete(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport)
{
	CALI_DEBUG("CT-TCP delete from %x:%d\n", be32_to_host(ip_src), sport);
	CALI_DEBUG("CT-TCP delete to   %x:%d\n", be32_to_host(ip_dst), dport);

	bool srcLTDest = src_lt_dest(ip_src, ip_dst, sport, dport);
	struct calico_ct_key k = ct_make_key(srcLTDest, IPPROTO_TCP, ip_src, ip_dst, sport, dport);

	int rc = cali_v4_ct_delete_elem(&k);
	CALI_DEBUG("CT-TCP delete result: %d\n", rc);
}

#define CALI_CT_LOG(level, fmt, ...) \
	CALI_LOG_IF_FLAG(level, CALI_COMPILE_FLAGS, "CT-%d "fmt, proto_orig, ## __VA_ARGS__)
#define CALI_CT_DEBUG(fmt, ...) \
	CALI_CT_LOG(CALI_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define CALI_CT_VERB(fmt, ...) \
	CALI_CT_LOG(CALI_LOG_LEVEL_VERB, fmt, ## __VA_ARGS__)

#define seqno_add(seq, add) (host_to_be32((be32_to_host(seq) + add)))

static CALI_BPF_INLINE void ct_tcp_entry_update(struct tcphdr *tcp_header,
						struct calico_ct_leg *src_to_dst,
						struct calico_ct_leg *dst_to_src)
{
	__u8 proto_orig = IPPROTO_TCP; /* used by logging */

	if (tcp_header->rst) {
		CALI_CT_DEBUG("RST seen, marking CT entry.\n");
		// TODO: We should only take account of RST packets that are in
		// the right window.
		// TODO if we trust the RST, could just drop the CT entries.
		src_to_dst->rst_seen = 1;
	}
	if (tcp_header->fin) {
		CALI_CT_VERB("FIN seen, marking CT entry.\n");
		src_to_dst->fin_seen = 1;
	}

	if (tcp_header->syn && tcp_header->ack) {
		if (dst_to_src->syn_seen && seqno_add(dst_to_src->seqno, 1) == tcp_header->ack_seq) {
			CALI_CT_VERB("SYN+ACK seen, marking CT entry.\n");
			src_to_dst->syn_seen = 1;
			src_to_dst->ack_seen = 1;
			src_to_dst->seqno = tcp_header->seq;
		} else {
			CALI_CT_VERB("SYN+ACK seen but packet's ACK (%u) "
					"doesn't match other side's SYN (%u).\n",
					be32_to_host(tcp_header->ack_seq),
					be32_to_host(dst_to_src->seqno));
			/* XXX Have to let this through so source can reset? */
		}
	} else if (tcp_header->ack && !src_to_dst->ack_seen && src_to_dst->syn_seen) {
		if (dst_to_src->syn_seen && seqno_add(dst_to_src->seqno, 1) == tcp_header->ack_seq) {
			CALI_CT_VERB("ACK seen, marking CT entry.\n");
			src_to_dst->ack_seen = 1;
		} else {
			CALI_CT_VERB("ACK seen but packet's ACK (%u) doesn't "
					"match other side's SYN (%u).\n",
					be32_to_host(tcp_header->ack_seq),
					be32_to_host(dst_to_src->seqno));
			/* XXX Have to let this through so source can reset? */
		}
	} else {
		/* Normal packet, check that the handshake is complete. */
		if (!dst_to_src->ack_seen) {
			CALI_CT_VERB("Non-flagged packet but other side has never ACKed.\n");
			/* XXX Have to let this through so source can reset? */
		} else {
			CALI_CT_VERB("Non-flagged packet and other side has ACKed.\n");
		}
	}
}

static CALI_BPF_INLINE struct calico_ct_result calico_ct_v4_lookup(struct ct_ctx *ctx)
{
	__u8 proto_orig = ctx->proto;
	__be32 ip_src = ctx->src;
	__be32 ip_dst = ctx->dst;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->dport;
	struct tcphdr *tcp_header = ctx->tcp;
	bool related = false;

	CALI_CT_DEBUG("lookup from %x:%d\n", be32_to_host(ip_src), sport);
	CALI_CT_DEBUG("lookup to   %x:%d\n", be32_to_host(ip_dst), dport);
	if (tcp_header) {
		CALI_CT_VERB("packet seq = %u\n", be32_to_host(tcp_header->seq));
		CALI_CT_VERB("packet ack_seq = %u\n", be32_to_host(tcp_header->ack_seq));
		CALI_CT_VERB("packet syn = %d\n", tcp_header->syn);
		CALI_CT_VERB("packet ack = %d\n", tcp_header->ack);
		CALI_CT_VERB("packet fin = %d\n", tcp_header->fin);
		CALI_CT_VERB("packet rst = %d\n", tcp_header->rst);
	}

	struct calico_ct_result result = {
		.rc = CALI_CT_NEW, /* it is zero, but make it explicit in the code */
	};

	if (tcp_header && tcp_header->syn && !tcp_header->ack) {
		// SYN should always go through policy.
		CALI_CT_DEBUG("Packet is a SYN, short-circuiting lookup.\n");
		goto out_lookup_fail;
	}

	bool srcLTDest = src_lt_dest(ip_src, ip_dst, sport, dport);
	struct calico_ct_key k = ct_make_key(srcLTDest, ctx->proto, ip_src, ip_dst, sport, dport);

	struct calico_ct_value *v = cali_v4_ct_lookup_elem(&k);
	if (!v) {
		if (ctx->proto != IPPROTO_ICMP) {
			CALI_CT_DEBUG("Miss.\n");
			goto out_lookup_fail;
		}
		if (!skb_is_icmp_err_unpack(ctx->skb, ctx)) {
			CALI_CT_DEBUG("unrelated icmp\n");
			goto out_lookup_fail;
		}

		CALI_CT_DEBUG("related lookup from %x:%d\n", be32_to_host(ctx->src), ctx->sport);
		CALI_CT_DEBUG("related lookup to   %x:%d\n", be32_to_host(ctx->dst), ctx->dport);

		srcLTDest = src_lt_dest(ctx->src, ctx->dst, ctx->sport, ctx->dport);
		k = ct_make_key(srcLTDest, ctx->proto, ctx->src, ctx->dst, ctx->sport, ctx->dport);
		v = cali_v4_ct_lookup_elem(&k);
		if (!v) {
			CALI_CT_DEBUG("Miss on ICMP related\n");
			goto out_lookup_fail;
		}

		ip_src = ctx->src;
		ip_dst = ctx->dst;
		sport = ctx->sport;
		dport = ctx->dport;
		tcp_header = ctx->tcp;

		related = true;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	result.flags = v->flags;

	struct calico_ct_leg *src_to_dst, *dst_to_src;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALI_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALI_CT_DEBUG("Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = cali_v4_ct_lookup_elem(&v->nat_rev_key);
		if (!tracking_v) {
			CALI_CT_DEBUG("Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			CALI_VERB("CT-ALL FWD-REV src_to_dst A->B\n");
			src_to_dst = &tracking_v->a_to_b;
			dst_to_src = &tracking_v->b_to_a;
			result.nat_ip = v->nat_rev_key.addr_b;
			result.nat_port = v->nat_rev_key.port_b;
		} else {
			CALI_VERB("CT-ALL FWD-REV src_to_dst B->A\n");
			src_to_dst = &tracking_v->b_to_a;
			dst_to_src = &tracking_v->a_to_b;
			result.nat_ip = v->nat_rev_key.addr_a;
			result.nat_port = v->nat_rev_key.port_a;
		}
		result.tun_ip = tracking_v->tun_ip;
		CALI_CT_DEBUG("fwd tun_ip:%x\n", be32_to_host(tracking_v->tun_ip));
		// flags are in the tracking entry
		result.flags = tracking_v->flags;

		if (ctx->proto == IPPROTO_ICMP) {
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
			result.nat_ip = tracking_v->orig_ip;
		} else if (CALI_F_TO_HOST) {
			// Since we found a forward NAT entry, we know that it's the destination
			// that needs to be NATted.
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
		} else {
			result.rc =	CALI_CT_ESTABLISHED;
		}

		/* If we are on a HEP - where encap/decap can happen - and if the packet
		 * arrived through a tunnel, check if the src IP of the packet is expected.
		 */
		if (CALI_F_FROM_HEP && ctx->tun_ip && result.tun_ip && result.tun_ip != ctx->tun_ip) {
			CALI_CT_DEBUG("tunnel src changed from %x to %x\n",
					be32_to_host(result.tun_ip), be32_to_host(ctx->tun_ip));
			ct_result_set_flag(result.rc, CALI_CT_TUN_SRC_CHANGED);
		}

		break;
	case CALI_CT_TYPE_NAT_REV:
		if (srcLTDest) {
			CALI_VERB("CT-ALL REV src_to_dst A->B\n");
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			CALI_VERB("CT-ALL REV src_to_dst B->A\n");
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		result.tun_ip = v->tun_ip;
		CALI_CT_DEBUG("tun_ip:%x\n", be32_to_host(v->tun_ip));

		if (ctx->proto == IPPROTO_ICMP || (related && proto_orig == IPPROTO_ICMP)) {
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_ip;
			result.nat_port = v->orig_port;
			break;
		}

		/* A reverse NAT entry; this means that the conntrack entry was
		 * keyed on the post-NAT IPs.  We _want_ to hit this entry where
		 * we need to do SNAT, however, we also hit this for request
		 * packets that traverse more than one endpoint on the same host
		 * so we need to distinguish those cases.
		 */
		int snat;

		/* Packet is heading away from the host namespace; either
		 * entering a workload or leaving via a host endpoint, actually
		 * reverse the NAT.
		 */
		snat = CALI_F_FROM_HOST;
		/* if returning packet into a tunnel */
		snat |= (dnat_return_should_encap() && v->tun_ip);
		snat = snat && dst_to_src->opener;

		if (snat) {
			CALI_CT_DEBUG("Hit! NAT REV entry at ingress to connection opener: SNAT.\n");
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_ip;
			result.nat_port = v->orig_port;
		} else {
			CALI_CT_DEBUG("Hit! NAT REV entry but not connection opener: ESTABLISHED.\n");
			result.rc =	CALI_CT_ESTABLISHED;
		}
		break;

	case CALI_CT_TYPE_NORMAL:
		CALI_CT_DEBUG("Hit! NORMAL entry.\n");
		CALI_CT_VERB("Created: %llu.\n", v->created);
		if (tcp_header) {
			CALI_CT_VERB("Last seen: %llu.\n", v->last_seen);
			CALI_CT_VERB("A-to-B: seqno %u.\n", be32_to_host(v->a_to_b.seqno));
			CALI_CT_VERB("A-to-B: syn_seen %d.\n", v->a_to_b.syn_seen);
			CALI_CT_VERB("A-to-B: ack_seen %d.\n", v->a_to_b.ack_seen);
			CALI_CT_VERB("A-to-B: fin_seen %d.\n", v->a_to_b.fin_seen);
			CALI_CT_VERB("A-to-B: rst_seen %d.\n", v->a_to_b.rst_seen);
		}
		CALI_CT_VERB("A: whitelisted %d.\n", v->a_to_b.whitelisted);
		if (tcp_header) {
			CALI_CT_VERB("B-to-A: seqno %u.\n", be32_to_host(v->b_to_a.seqno));
			CALI_CT_VERB("B-to-A: syn_seen %d.\n", v->b_to_a.syn_seen);
			CALI_CT_VERB("B-to-A: ack_seen %d.\n", v->b_to_a.ack_seen);
			CALI_CT_VERB("B-to-A: fin_seen %d.\n", v->b_to_a.fin_seen);
			CALI_CT_VERB("B-to-A: rst_seen %d.\n", v->b_to_a.rst_seen);
		}
		CALI_CT_VERB("B: whitelisted %d.\n", v->b_to_a.whitelisted);

		if (tcp_header && v->a_to_b.whitelisted && v->b_to_a.whitelisted) {
			result.rc = CALI_CT_ESTABLISHED_BYPASS;
		} else {
			result.rc = CALI_CT_ESTABLISHED;
		}

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		break;
	default:
		CALI_CT_DEBUG("Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	int ret_from_tun = CALI_F_FROM_HEP &&
				ctx->tun_ip &&
				result.rc == CALI_CT_ESTABLISHED_DNAT &&
				src_to_dst->whitelisted &&
				result.flags & CALI_CT_FLAG_NP_FWD;

	if (related) {
		if (proto_orig == IPPROTO_ICMP) {
			/* flip src/dst as ICMP related carries the original ip/l4 headers in
			 * opposite direction - it is a reaction on the original packet.
			 */
			struct calico_ct_leg *tmp;

			tmp = src_to_dst;
			src_to_dst = dst_to_src;
			dst_to_src = tmp;
		}
	}

	if (ret_from_tun) {
		CALI_DEBUG("Packet returned from tunnel %x\n", be32_to_host(ctx->tun_ip));
	} else if (CALI_F_TO_HOST) {
		/* Source of the packet is the endpoint, so check the src whitelist. */
		if (src_to_dst->whitelisted) {
			CALI_CT_VERB("Packet whitelisted by this workload's policy.\n");
		} else {
			/* Only whitelisted by the other side (so far)?  Unlike
			 * TCP we have no way to distinguish packets that open a
			 * new connection so we have to return NEW here in order
			 * to invoke policy.
			 */
			CALI_CT_DEBUG("Packet not allowed by ingress/egress whitelist flags (TH).\n");
			result.rc = tcp_header ? CALI_CT_INVALID : CALI_CT_NEW;
		}
	} if (CALI_F_FROM_HOST) {
		/* Dest of the packet is the workload, so check the dest whitelist. */
		if (dst_to_src->whitelisted) {
			// Packet was whitelisted by the policy attached to this endpoint.
			CALI_CT_VERB("Packet whitelisted by this workload's policy.\n");
		} else {
			/* Only whitelisted by the other side (so far)?  Unlike
			 * TCP we have no way to distinguish packets that open a
			 * new connection so we have to return NEW here in order
			 * to invoke policy.
			 */
			CALI_CT_DEBUG("Packet not allowed by ingress/egress whitelist flags (FH).\n");
			result.rc = tcp_header ? CALI_CT_INVALID : CALI_CT_NEW;
		}
	}

	if (tcp_header && !related) {
		if (ret_from_tun) {
			/* we returned from tunnel, we are after SNAT, unlike
			 * with NAT on workload, we hit FWD entry in both
			 * directions, so we need to swap the direction.
			 */
			struct calico_ct_leg *tmp = dst_to_src;

			dst_to_src = src_to_dst;
			src_to_dst = tmp;
		}
		ct_tcp_entry_update(tcp_header, src_to_dst, dst_to_src);
	}

	__u32 ifindex = skb_ingress_ifindex(ctx->skb);

	if (src_to_dst->ifindex != ifindex) {
		if (CALI_F_TO_HOST) {
			if (src_to_dst->ifindex == CT_INVALID_IFINDEX) {
				/* we have not recorded the path for the opposite
				 * direction yet, do it now.
				 */
				src_to_dst->ifindex = ifindex;
				CALI_DEBUG("REV src_to_dst->ifindex %d\n", src_to_dst->ifindex);
			} else {
				CALI_CT_DEBUG("RPF expected %d to equal %d\n",
						src_to_dst->ifindex, ifindex);
				if (ct_result_rc(result.rc) == CALI_CT_ESTABLISHED_BYPASS) {
					ct_result_set_rc(result.rc, CALI_CT_ESTABLISHED);
				}
				ct_result_set_flag(result.rc, CALI_CT_RPF_FAILED);
			}
		} else {
			/* if the devices do not match, we got here without bypassing the
			 * host IP stack and RPF check allowed it, so update our records.
			 */
			CALI_CT_DEBUG("Updating ifindex from %d to %d\n",
					src_to_dst->ifindex, ifindex);
			src_to_dst->ifindex = ifindex;
		}
	}

	if (CALI_F_TO_HOST) {
		/* Fill in the ifindex we recorded in the opposite direction. The caller
		 * may use it directly forward the packet to the same interface where
		 * packets in the opposite direction are coming from.
		 */
		result.ifindex_fwd = dst_to_src->ifindex;
	}

	CALI_CT_DEBUG("result: %d\n", result.rc);

	if (related) {
		ct_result_set_flag(result.rc, CALI_CT_RELATED);
		CALI_CT_DEBUG("result: related\n");
	}

	return result;

out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_CT_DEBUG("result: NEW.\n");
	return result;
}

/* creates connection tracking for tracked protocols */
static CALI_BPF_INLINE int conntrack_create(struct ct_ctx * ctx, int nat)
{
	switch (ctx->proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		switch (nat) {
		case CT_CREATE_NORMAL:
			return calico_ct_v4_create(ctx);
		case CT_CREATE_NAT:
		case CT_CREATE_NAT_FWD:
			return calico_ct_v4_create_nat(ctx, nat);
		}
		return 0;
	default:
		return 0;
	}
}

#endif /* __CALI_CONNTRACK_H__ */
