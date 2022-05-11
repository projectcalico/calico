// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_CONNTRACK_H__
#define __CALI_CONNTRACK_H__

#include <linux/in.h>
#include "nat.h"
#include "bpf.h"
#include "icmp.h"
#include "types.h"
#include "rpf.h"

// Connection tracking.

#define PSNAT_RETRIES	3

static CALI_BPF_INLINE int psnat_get_port(void)
{
	return PSNAT_START + (bpf_get_prandom_u32() % PSNAT_LEN);
}

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

#define ct_result_np_node(res)		((res).flags & CALI_CT_FLAG_NP_FWD)

static CALI_BPF_INLINE void dump_ct_key(struct calico_ct_key *k)
{
	CALI_VERB("CT-ALL   key A=%x:%d proto=%d\n", bpf_ntohl(k->addr_a), k->port_a, (int)k->protocol);
	CALI_VERB("CT-ALL   key B=%x:%d size=%d\n", bpf_ntohl(k->addr_b), k->port_b, (int)sizeof(struct calico_ct_key));
}

static CALI_BPF_INLINE int calico_ct_v4_create_tracking(struct ct_create_ctx *ct_ctx,
							struct calico_ct_key *k)
{
	__be32 ip_src = ct_ctx->src;
	__be32 ip_dst = ct_ctx->dst;
	__u16 sport = ct_ctx->sport;
	__u16 dport = ct_ctx->dport;
	__be32 orig_dst = ct_ctx->orig_dst;
	__u16 orig_dport = ct_ctx->orig_dport;
	int err = 0;


	__be32 seq = 0;
	bool syn = false;
	__u64 now;

	if (ct_ctx->tcp) {
		seq = ct_ctx->tcp->seq;
		syn = ct_ctx->tcp->syn;
	}

	CALI_DEBUG("CT-ALL packet mark is: 0x%x\n", ct_ctx->skb->mark);
	if (skb_seen(ct_ctx->skb)) {
		/* Packet already marked as being from another workload, which will
		 * have created a conntrack entry.  Look that one up instead of
		 * creating one.
		 */
		CALI_DEBUG("CT-ALL Asked to create entry but packet is marked as "
				"from another endpoint, doing lookup\n");
		bool srcLTDest = src_lt_dest(ip_src, ip_dst, sport, dport);
		*k = ct_make_key(srcLTDest, ct_ctx->proto, ip_src, ip_dst, sport, dport);
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
	CALI_DEBUG("CT-ALL Creating tracking entry type %d at %llu.\n", ct_ctx->type, now);

	struct calico_ct_value ct_value = {
		.created=now,
		.last_seen=now,
		.type = ct_ctx->type,
		.orig_ip = orig_dst,
		.orig_port = orig_dport,
	};

	ct_value_set_flags(&ct_value, ct_ctx->flags);
	CALI_DEBUG("CT-ALL tracking entry flags 0x%x\n", ct_value_get_flags(&ct_value));

	ct_value.orig_sip = ct_ctx->orig_src;
	ct_value.orig_sport = ct_ctx->orig_sport;
	CALI_DEBUG("CT-ALL SNAT orig %x:%d\n", bpf_htonl(ct_ctx->orig_src),  ct_ctx->orig_sport);


	if (ct_ctx->type == CALI_CT_TYPE_NAT_REV && ct_ctx->tun_ip) {
		if (ct_ctx->flags & CALI_CT_FLAG_NP_FWD) {
			CALI_DEBUG("CT-ALL nat tunneled to %x\n", bpf_ntohl(ct_ctx->tun_ip));
		} else {
			struct cali_rt *rt = cali_rt_lookup(ct_ctx->tun_ip);
			if (!rt || !cali_rt_is_host(rt)) {
				CALI_DEBUG("CT-ALL nat tunnel IP not a host %x\n", bpf_ntohl(ct_ctx->tun_ip));
				err = -1;
				goto out;
			}
			CALI_DEBUG("CT-ALL nat tunneled from %x\n", bpf_ntohl(ct_ctx->tun_ip));
		}
		ct_value.tun_ip = ct_ctx->tun_ip;
	}

	struct calico_ct_leg *src_to_dst, *dst_to_src;
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);

	if (srcLTDest) {
		*k = (struct calico_ct_key) {
			.protocol = ct_ctx->proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		CALI_VERB("CT-ALL src_to_dst A->B\n");
		src_to_dst = &ct_value.a_to_b;
		dst_to_src = &ct_value.b_to_a;
	} else  {
		*k = (struct calico_ct_key) {
			.protocol = ct_ctx->proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		CALI_VERB("CT-ALL src_to_dst B->A\n");
		src_to_dst = &ct_value.b_to_a;
		dst_to_src = &ct_value.a_to_b;
		ct_value_set_flags(&ct_value, CALI_CT_FLAG_BA);
	}

	dump_ct_key(k);

	src_to_dst->seqno = seq;
	src_to_dst->syn_seen = syn;
	src_to_dst->opener = 1;
	if (CALI_F_TO_HOST) {
		src_to_dst->ifindex = skb_ingress_ifindex(ct_ctx->skb);
	} else {
		src_to_dst->ifindex = CT_INVALID_IFINDEX;
	}
	CALI_DEBUG("NEW src_to_dst->ifindex %d\n", src_to_dst->ifindex);
	dst_to_src->ifindex = CT_INVALID_IFINDEX;

	if (CALI_F_FROM_WEP) {
		/* src is the from the WEP, policy whitelisted this side */
		src_to_dst->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted source side - from WEP\n");
	} else if (CALI_F_FROM_HEP) {
		/* src is the from the HEP, policy whitelisted this side */
		src_to_dst->whitelisted = 1;

		if (ct_ctx->allow_return) {
			/* When we do NAT and forward through the tunnel, we go through
			 * a single policy, what we forward we also accept back,
			 * whitelist both sides.
			 */
			dst_to_src->whitelisted = 1;
		}
		CALI_DEBUG("CT-ALL Whitelisted source side - from HEP tun allow_return=%d\n",
				ct_ctx->allow_return);
	} else if (CALI_F_TO_HEP && !skb_seen(ct_ctx->skb) && (ct_ctx->type == CALI_CT_TYPE_NAT_REV)) {
		src_to_dst->whitelisted = 1;
		dst_to_src->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted both due to host source port conflict resolution.\n");
	} else if (CALI_F_FROM_HOST) {
		/* dst is to the EP, policy whitelisted this side */
		dst_to_src->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted dest side - to EP\n");
	}

	err = cali_v4_ct_update_elem(k, &ct_value, BPF_NOEXIST);

	if (CALI_F_HEP && err == -17 /* EEXIST */) {
		int i;

		CALI_DEBUG("Source collision for 0x%x:%d\n", bpf_htonl(ip_src), sport);

		ct_value.orig_sport = sport;

		for (i = 0; i < PSNAT_RETRIES; i++) {
			sport = psnat_get_port();
			CALI_DEBUG("New sport %d\n", sport);

			bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);

			*k = ct_make_key(srcLTDest, ct_ctx->proto, ip_src, ip_dst, sport, dport);

			if (!(err = cali_v4_ct_update_elem(k, &ct_value, BPF_NOEXIST))) {
				ct_ctx->sport = sport;
				break;
			}
		}

		if (i == PSNAT_RETRIES) {
			CALI_INFO("Source collision unresolved 0x%x:%d\n",
					bpf_htonl(ip_src), ct_value.orig_sport);
		}
	}

out:
	CALI_VERB("CT-ALL Create result: %d.\n", err);
	return err;
}

static CALI_BPF_INLINE int calico_ct_v4_create_nat_fwd(struct ct_create_ctx *ct_ctx,
						       struct calico_ct_key *rk)
{
	__u8 ip_proto = ct_ctx->proto;
	__be32 ip_src = ct_ctx->orig_src;
	__be32 ip_dst = ct_ctx->orig_dst;
	__u16 sport = ct_ctx->orig_sport;
	__u16 dport = ct_ctx->orig_dport;

	if (CALI_F_TO_HEP && !CALI_F_NAT_IF && sport != ct_ctx->sport &&
			!(ct_ctx->skb->mark & (CALI_SKB_MARK_FROM_NAT_IFACE_OUT | CALI_SKB_MARK_SEEN))) {
		/* This entry is being created because we have a source port
		 * conflict on a connection from host. We did psnat so we mak
		 * such an entry with a 0 sport.
		 */
		sport = 0;
		CALI_DEBUG("FWD for psnat host conflict\n");
	}

	__u64 now = bpf_ktime_get_ns();

	CALI_DEBUG("CT-%d Creating FWD entry at %llu.\n", ip_proto, now);
	CALI_DEBUG("FWD %x -> %x\n", bpf_ntohl(ip_src), bpf_ntohl(ip_dst));
	struct calico_ct_value ct_value = {
		.type = CALI_CT_TYPE_NAT_FWD,
		.last_seen = now,
		.created = now,
	};

	struct calico_ct_key k;
	bool srcLTDest = src_lt_dest(ip_src, ip_dst, sport, dport);
	k = ct_make_key(srcLTDest, ct_ctx->proto, ip_src, ip_dst, sport, dport);

	ct_value.nat_rev_key = *rk;
	if (ct_ctx->orig_sport != ct_ctx->sport) {
		ct_value.nat_sport = ct_ctx->sport;
	}
	int err = cali_v4_ct_update_elem(&k, &ct_value, 0);
	CALI_VERB("CT-%d Create result: %d.\n", ip_proto, err);
	return err;
}

/* skb_icmp_err_unpack tries to unpack the inner IP and TCP/UDP header from an ICMP error message.
 * It updates the ct_ctx with the protocol/src/dst/ports of the inner packet.  If the unpack fails
 * (due to packet too short, for example), it returns false and sets the RC in the cali_tc_ctx to
 * TC_ACT_SHOT.
 */
static CALI_BPF_INLINE bool skb_icmp_err_unpack(struct cali_tc_ctx *ctx, struct ct_lookup_ctx *ct_ctx)
{
	/* ICMP packet is an error, its payload should contain the full IP header and
	 * at least the first 8 bytes of the next header. */

	if (skb_refresh_validate_ptrs(ctx, ICMP_SIZE + sizeof(struct iphdr) + 8)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		ctx->fwd.res = TC_ACT_SHOT;
		CALI_DEBUG("ICMP v4 reply: too short getting hdr\n");
		return false;
	}

	struct iphdr *ip_inner;
	ip_inner = (struct iphdr *)(tc_icmphdr(ctx) + 1); /* skip to inner ip */
	CALI_DEBUG("CT-ICMP: proto %d\n", ip_inner->protocol);

	ct_ctx->proto = ip_inner->protocol;
	ct_ctx->src = ip_inner->saddr;
	ct_ctx->dst = ip_inner->daddr;

	switch (ip_inner->protocol) {
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(ip_inner + 1);
			ct_ctx->sport = bpf_ntohs(tcp->source);
			ct_ctx->dport = bpf_ntohs(tcp->dest);
			ct_ctx->tcp = tcp;
		}
		break;
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)(ip_inner + 1);
			ct_ctx->sport = bpf_ntohs(udp->source);
			ct_ctx->dport = bpf_ntohs(udp->dest);
		}
		break;
	};

	return true;
}

static CALI_BPF_INLINE void calico_ct_v4_tcp_delete(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport)
{
	CALI_DEBUG("CT-TCP delete from %x:%d\n", bpf_ntohl(ip_src), sport);
	CALI_DEBUG("CT-TCP delete to   %x:%d\n", bpf_ntohl(ip_dst), dport);

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

#define seqno_add(seq, add) (bpf_htonl((bpf_ntohl(seq) + add)))

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
					bpf_ntohl(tcp_header->ack_seq),
					bpf_ntohl(dst_to_src->seqno));
			/* XXX Have to let this through so source can reset? */
		}
	} else if (tcp_header->ack && !src_to_dst->ack_seen && src_to_dst->syn_seen) {
		if (dst_to_src->syn_seen && seqno_add(dst_to_src->seqno, 1) == tcp_header->ack_seq) {
			CALI_CT_VERB("ACK seen, marking CT entry.\n");
			src_to_dst->ack_seen = 1;
		} else {
			CALI_CT_VERB("ACK seen but packet's ACK (%u) doesn't "
					"match other side's SYN (%u).\n",
					bpf_ntohl(tcp_header->ack_seq),
					bpf_ntohl(dst_to_src->seqno));
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

static CALI_BPF_INLINE bool tcp_recycled(bool syn, struct calico_ct_value *v)
{
	struct calico_ct_leg *a, *b;

	a = &v->a_to_b;
	b = &v->b_to_a;

	/* When we see a SYN for a connection that has seen FIN or RST in both direction,
	 * a new connection with the same tuple is trying to recycle this entry.
	 */
	return syn && (a->fin_seen || a->rst_seen) && (b->fin_seen || b->rst_seen);
}

static CALI_BPF_INLINE struct calico_ct_result calico_ct_v4_lookup(struct cali_tc_ctx *tc_ctx)
{
	// TODO: refactor the conntrack code to simply use the tc_ctx instead of its own.  This
	// code is a direct translation of the pre-tc_ctx code so it has some duplication (but it
	// needs a bit more analysis to sort out because the ct_ctx gets modified in place in
	// ways that might not make sense to expose through the tc_ctx.
	struct ct_lookup_ctx ct_lookup_ctx = {
		.proto	= tc_ctx->state->ip_proto,
		.src	= tc_ctx->state->ip_src,
		.sport	= tc_ctx->state->sport,
		.dst	= tc_ctx->state->ip_dst,
		.dport	= tc_ctx->state->dport,
	};
	struct ct_lookup_ctx *ct_ctx = &ct_lookup_ctx;

	switch (tc_ctx->state->ip_proto) {
	case IPPROTO_TCP:
		if (skb_refresh_validate_ptrs(tc_ctx, TCP_SIZE)) {
			tc_ctx->fwd.reason = CALI_REASON_SHORT;
			CALI_DEBUG("Too short\n");
			bpf_exit(TC_ACT_SHOT);
		}
		ct_lookup_ctx.tcp = tc_tcphdr(tc_ctx);
		break;
	case IPPROTO_ICMP:
		// There are no port in ICMP and the fields in state are overloaded
		// for other use like type and code.
		ct_lookup_ctx.dport = ct_lookup_ctx.sport = 0;
		break;
	}

	__u8 proto_orig = ct_ctx->proto;
	__be32 ip_src = ct_ctx->src;
	__be32 ip_dst = ct_ctx->dst;
	__u16 sport = ct_ctx->sport;
	__u16 dport = ct_ctx->dport;
	struct tcphdr *tcp_header = ct_ctx->tcp;
	bool related = false;

	CALI_CT_DEBUG("lookup from %x:%d\n", bpf_ntohl(ip_src), sport);
	CALI_CT_DEBUG("lookup to   %x:%d\n", bpf_ntohl(ip_dst), dport);
	if (tcp_header) {
		CALI_CT_VERB("packet seq = %u\n", bpf_ntohl(tcp_header->seq));
		CALI_CT_VERB("packet ack_seq = %u\n", bpf_ntohl(tcp_header->ack_seq));
		CALI_CT_VERB("packet syn = %d\n", tcp_header->syn);
		CALI_CT_VERB("packet ack = %d\n", tcp_header->ack);
		CALI_CT_VERB("packet fin = %d\n", tcp_header->fin);
		CALI_CT_VERB("packet rst = %d\n", tcp_header->rst);
	}

	struct calico_ct_result result = {
		.rc = CALI_CT_NEW, /* it is zero, but make it explicit in the code */
		.ifindex_created = CT_INVALID_IFINDEX,
	};

	bool srcLTDest = src_lt_dest(ip_src, ip_dst, sport, dport);
	struct calico_ct_key k = ct_make_key(srcLTDest, ct_ctx->proto, ip_src, ip_dst, sport, dport);
	bool syn = tcp_header && tcp_header->syn && !tcp_header->ack;

	struct calico_ct_value *v = cali_v4_ct_lookup_elem(&k);
	if (!v) {
		if (syn) {
			// SYN packet (new flow); send it to policy.
			CALI_CT_DEBUG("Miss for TCP SYN, NEW flow.\n");
			goto out_lookup_fail;
		}
		if (CALI_F_FROM_HOST && proto_orig == IPPROTO_TCP) {
			// Mid-flow TCP packet with no conntrack entry leaving the host namespace.
			CALI_DEBUG("BPF CT Miss for mid-flow TCP\n");
			if ((tc_ctx->skb->mark & CALI_SKB_MARK_CT_ESTABLISHED_MASK) == CALI_SKB_MARK_CT_ESTABLISHED) {
				// Linux Conntrack has marked the packet as part of an established flow.
				// TODO-HEP Create a tracking entry for uplifted flow so that we handle the reverse traffic more efficiently.
				 CALI_DEBUG("BPF CT Miss but have Linux CT entry: established\n");
				 result.rc = CALI_CT_ESTABLISHED;
				 return result;
			}
			CALI_DEBUG("BPF CT Miss but Linux CT entry not signalled\n");
			result.rc = CALI_CT_MID_FLOW_MISS;
			return result;
		}
		if (CALI_F_TO_HOST && proto_orig == IPPROTO_TCP) {
			// Miss for a mid-flow TCP packet towards the host.  This may be part of a
			// connection that predates the BPF program so we need to let it fall through
			// to iptables.
			CALI_DEBUG("BPF CT Miss for mid-flow TCP\n");
			result.rc = CALI_CT_MID_FLOW_MISS;
			return result;
		}
		if (ct_ctx->proto != IPPROTO_ICMP) {
			// Not ICMP so can't be a "related" packet.
			CALI_CT_DEBUG("Miss.\n");
			goto out_lookup_fail;
		}

		if (!icmp_type_is_err(tc_icmphdr(tc_ctx)->type)) {
			// ICMP but not an error response packet.
			CALI_DEBUG("CT-ICMP: type %d not an error\n",
					tc_icmphdr(tc_ctx)->type);
			goto out_lookup_fail;
		}

		// ICMP error packets are a response to a failed UDP/TCP/etc packet.  Try to extract the
		// details of the inner packet.
		if (!skb_icmp_err_unpack(tc_ctx, ct_ctx)) {
			CALI_CT_DEBUG("Failed to parse ICMP error packet.\n");
			goto out_invalid;
		}

		// skb_icmp_err_unpack updates the ct_ctx with the details of the inner packet;
		// look for a conntrack entry for the inner packet...
		CALI_CT_DEBUG("related lookup from %x:%d\n", bpf_ntohl(ct_ctx->src), ct_ctx->sport);
		CALI_CT_DEBUG("related lookup to   %x:%d\n", bpf_ntohl(ct_ctx->dst), ct_ctx->dport);

		srcLTDest = src_lt_dest(ct_ctx->src, ct_ctx->dst, ct_ctx->sport, ct_ctx->dport);
		k = ct_make_key(srcLTDest, ct_ctx->proto, ct_ctx->src, ct_ctx->dst, ct_ctx->sport, ct_ctx->dport);
		v = cali_v4_ct_lookup_elem(&k);
		if (!v) {
			if (CALI_F_FROM_HOST &&
				ct_ctx->proto == IPPROTO_TCP &&
				(tc_ctx->skb->mark & CALI_SKB_MARK_CT_ESTABLISHED_MASK) == CALI_SKB_MARK_CT_ESTABLISHED) {
				// Linux Conntrack has marked the packet as part of a known flow.
				// TODO-HEP Create a tracking entry for uplifted flow so that we handle the reverse traffic more efficiently.
				CALI_DEBUG("BPF CT related miss but have Linux CT entry: established\n");
				result.rc = CALI_CT_ESTABLISHED;
				return result;
			}

			if (CALI_F_TO_HOST && ct_ctx->proto == IPPROTO_TCP) {
				// Miss for a related packet towards the host.  This may be part of a
				// connection that predates the BPF program so we need to let it fall through
				// to iptables.
				CALI_DEBUG("BPF CT related miss for mid-flow TCP\n");
				result.rc = CALI_CT_MID_FLOW_MISS;
				return result;
			}

			CALI_CT_DEBUG("Miss on ICMP related\n");
			goto out_lookup_fail;
		}

		ip_src = ct_ctx->src;
		ip_dst = ct_ctx->dst;
		sport = ct_ctx->sport;
		dport = ct_ctx->dport;
		tcp_header = ct_ctx->tcp;

		related = true;

		// We failed to look up the original flow, but it is an ICMP error and we
		// _do_ have a CT entry for the packet inside the error.  ct_ctx has been
		// updated to describe the inner packet.
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	result.flags = ct_value_get_flags(v);

	// Return the if_index where the CT state was created.
	if (v->a_to_b.opener) {
		result.ifindex_created = v->a_to_b.ifindex;
	} else if (v->b_to_a.opener) {
		result.ifindex_created = v->b_to_a.ifindex;
	}

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
		if (tcp_recycled(syn, tracking_v)) {
			CALI_CT_DEBUG("TCP SYN recycles entry, NEW flow.\n");
			cali_v4_ct_delete_elem(&k);
			cali_v4_ct_delete_elem(&v->nat_rev_key);
			goto out_lookup_fail;
		}

		// Record timestamp.
		tracking_v->last_seen = now;

		if (!(ct_value_get_flags(tracking_v) & CALI_CT_FLAG_BA)) {
			CALI_VERB("CT-ALL FWD-REV src_to_dst A->B\n");
			src_to_dst = &tracking_v->a_to_b;
			dst_to_src = &tracking_v->b_to_a;
			result.nat_ip = v->nat_rev_key.addr_b;
			result.nat_port = v->nat_rev_key.port_b;
			result.nat_sip = v->nat_rev_key.addr_a;
			result.nat_sport = v->nat_rev_key.port_a;
		} else {
			CALI_VERB("CT-ALL FWD-REV src_to_dst B->A\n");
			src_to_dst = &tracking_v->b_to_a;
			dst_to_src = &tracking_v->a_to_b;
			result.nat_ip = v->nat_rev_key.addr_a;
			result.nat_port = v->nat_rev_key.port_a;
			result.nat_sip = v->nat_rev_key.addr_b;
			result.nat_sport = v->nat_rev_key.port_b;
		}

		if (v->nat_sport) {
			/* This would override the host SNAT, but those two features are
			 * mutually exclusive. One happens for nodeport only (psnat) the
			 * other for host -> service only (full SNAT)
			 */
			result.nat_sport = v->nat_sport;
		}

		result.tun_ip = tracking_v->tun_ip;
		CALI_CT_DEBUG("fwd tun_ip:%x\n", bpf_ntohl(tracking_v->tun_ip));
		// flags are in the tracking entry
		result.flags = ct_value_get_flags(tracking_v);

		if (ct_ctx->proto == IPPROTO_ICMP) {
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
		if (CALI_F_FROM_HEP && tc_ctx->state->tun_ip && result.tun_ip && result.tun_ip != tc_ctx->state->tun_ip) {
			CALI_CT_DEBUG("tunnel src changed from %x to %x\n",
					bpf_ntohl(result.tun_ip), bpf_ntohl(tc_ctx->state->tun_ip));
			ct_result_set_flag(result.rc, CALI_CT_TUN_SRC_CHANGED);
		}

		break;
	case CALI_CT_TYPE_NAT_REV:
		// N.B. we do not check for tcp_recycled because this cannot be the first
		// SYN that is opening a new connection. This must be returning traffic.
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
		CALI_CT_DEBUG("tun_ip:%x\n", bpf_ntohl(v->tun_ip));

		result.flags = ct_value_get_flags(v);

		if (ct_ctx->proto == IPPROTO_ICMP || (related && proto_orig == IPPROTO_ICMP)) {
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_ip;
			result.nat_port = v->orig_port;
			result.nat_sip = v->orig_sip;
			result.nat_sport = v->orig_sport;
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
		snat |= result.flags & CALI_CT_FLAG_VIA_NAT_IF;
		snat |= result.flags & CALI_CT_FLAG_HOST_PSNAT;
		snat = snat && dst_to_src->opener;

		if (snat) {
			CALI_CT_DEBUG("Hit! NAT REV entry at ingress to connection opener: SNAT.\n");
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_ip;
			result.nat_sip = v->orig_sip;
			result.nat_port = v->orig_port;
			result.nat_sport = v->orig_sport;
		} else {
			CALI_CT_DEBUG("Hit! NAT REV entry but not connection opener: ESTABLISHED.\n");
			result.rc =	CALI_CT_ESTABLISHED;
		}
		break;

	case CALI_CT_TYPE_NORMAL:
		CALI_CT_DEBUG("Hit! NORMAL entry.\n");
		if (tcp_recycled(syn, v)) {
			CALI_CT_DEBUG("TCP SYN recycles entry, NEW flow.\n");
			cali_v4_ct_delete_elem(&k);
			goto out_lookup_fail;
		}
		CALI_CT_VERB("Created: %llu.\n", v->created);
		if (tcp_header) {
			CALI_CT_VERB("Last seen: %llu.\n", v->last_seen);
			CALI_CT_VERB("A-to-B: seqno %u.\n", bpf_ntohl(v->a_to_b.seqno));
			CALI_CT_VERB("A-to-B: syn_seen %d.\n", v->a_to_b.syn_seen);
			CALI_CT_VERB("A-to-B: ack_seen %d.\n", v->a_to_b.ack_seen);
			CALI_CT_VERB("A-to-B: fin_seen %d.\n", v->a_to_b.fin_seen);
			CALI_CT_VERB("A-to-B: rst_seen %d.\n", v->a_to_b.rst_seen);
		}
		CALI_CT_VERB("A: whitelisted %d.\n", v->a_to_b.whitelisted);
		if (tcp_header) {
			CALI_CT_VERB("B-to-A: seqno %u.\n", bpf_ntohl(v->b_to_a.seqno));
			CALI_CT_VERB("B-to-A: syn_seen %d.\n", v->b_to_a.syn_seen);
			CALI_CT_VERB("B-to-A: ack_seen %d.\n", v->b_to_a.ack_seen);
			CALI_CT_VERB("B-to-A: fin_seen %d.\n", v->b_to_a.fin_seen);
			CALI_CT_VERB("B-to-A: rst_seen %d.\n", v->b_to_a.rst_seen);
		}
		CALI_CT_VERB("B: whitelisted %d.\n", v->b_to_a.whitelisted);

		if (v->a_to_b.whitelisted && v->b_to_a.whitelisted) {
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
				tc_ctx->state->tun_ip &&
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
		CALI_DEBUG("Packet returned from tunnel %x\n", bpf_ntohl(tc_ctx->state->tun_ip));
	} else if (CALI_F_TO_HOST || (skb_from_host(tc_ctx->skb) && result.flags & CALI_CT_FLAG_HOST_PSNAT)) {
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
	} else if (CALI_F_FROM_HOST) {
		/* Dest of the packet is the endpoint, so check the dest whitelist. */
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
			result.rc = (tcp_header && !syn) ? CALI_CT_INVALID : CALI_CT_NEW;
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

	__u32 ifindex = skb_ingress_ifindex(tc_ctx->skb);

	if (src_to_dst->ifindex != ifindex) {
		// Conntrack entry records a different ingress interface than the one the
		// packet arrived on (or it has no record yet).
		if (CALI_F_TO_HOST) {
			// Packet is towards the host so this program is the first to see the packet.
			if (src_to_dst->ifindex == CT_INVALID_IFINDEX) {
				// Conntrack entry has no record of the ingress interface, this should
				// be a response packet but we can't be 100% sure.
				CALI_CT_DEBUG("First response packet? ifindex=%d\n", ifindex);
			} else {
				// The interface has changed; either a change to routing or someone's doing
				// something nasty.
				CALI_CT_DEBUG("CT RPF failed ifindex %d != %d\n",
						src_to_dst->ifindex, ifindex);
			}
			if (!ret_from_tun && !hep_rpf_check(tc_ctx)) {
				ct_result_set_flag(result.rc, CALI_CT_RPF_FAILED);
			} else {
				src_to_dst->ifindex = ifindex;
			}
		} else if (src_to_dst->ifindex != CT_INVALID_IFINDEX) {
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

	if (syn) {
		CALI_CT_DEBUG("packet is SYN\n");
		ct_result_set_flag(result.rc, CALI_CT_SYN);
	}


	CALI_CT_DEBUG("result: 0x%x\n", result.rc);

	if (related) {
		ct_result_set_flag(result.rc, CALI_CT_RELATED);
		CALI_CT_DEBUG("result: related\n");
	}

	return result;

out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_CT_DEBUG("result: NEW.\n");
	return result;
out_invalid:
	result.rc = CALI_CT_INVALID;
	CALI_CT_DEBUG("result: INVALID.\n");
	return result;
}

/* creates connection tracking for tracked protocols */
static CALI_BPF_INLINE int conntrack_create(struct cali_tc_ctx *ctx, struct ct_create_ctx *ct_ctx)
{
	struct calico_ct_key k;
	int err;

	if (ctx->state->flags & CALI_ST_SUPPRESS_CT_STATE) {
		// CT state creation is suppressed.
		return 0;
	}

	// Workaround for verifier; make sure verifier sees the skb on all code paths.
	ct_ctx->skb = ctx->skb;

	err = calico_ct_v4_create_tracking(ct_ctx, &k);
	if (err) {
		CALI_DEBUG("calico_ct_v4_create_tracking err %d\n", err);
		return err;
	}

	if (ct_ctx->type == CALI_CT_TYPE_NAT_REV) {
		err = calico_ct_v4_create_nat_fwd(ct_ctx, &k);
		if (err) {
			/* XXX we should clean up the tracking entry */
		}
	}

	return err;
}

#endif /* __CALI_CONNTRACK_H__ */
