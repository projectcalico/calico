// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_CONNTRACK_H__
#define __CALI_CONNTRACK_H__

#include <linux/in.h>
#include "nat.h"
#include "bpf.h"
#include "icmp.h"
#include "types.h"
#include "rpf.h"

#ifdef IPVER6
#define IPPROTO_ICMP_46	IPPROTO_ICMPV6
#else
#define IPPROTO_ICMP_46	IPPROTO_ICMP
#endif

// Connection tracking.

#define PSNAT_RETRIES	3

static CALI_BPF_INLINE int psnat_get_port(struct cali_tc_ctx *ctx)
{
	return PSNAT_START + (bpf_get_prandom_u32() % PSNAT_LEN);
}

#ifdef IPVER6

static CALI_BPF_INLINE bool  src_lt_dest(ipv6_addr_t *ip_src, ipv6_addr_t *ip_dst, __u16 sport, __u16 dport)
{
	int ret = ipv6_addr_t_cmp(ip_src, ip_dst);

	if (ret != 0) {
		return ret < 0;
	}

	return sport < dport;
}

#else

#define src_lt_dest(ip_src, ip_dst, sport, dport) \
	(*(ip_src) < *(ip_dst)) || ((*(ip_src) == *(ip_dst)) && (sport) < (dport))

#endif /* IPVER6 */

static CALI_BPF_INLINE void fill_ct_key(struct calico_ct_key *k, bool sltd, __u8 proto,
					ipv46_addr_t *ipa, ipv46_addr_t *ipb, __u16 pta, __u16 ptb)
{
	k->protocol = proto;

	if (sltd) {
		k->addr_a = *ipa;
		k->addr_b = *ipb;
		k->port_a = pta;
		k->port_b = ptb;
	} else {
		k->addr_a = *ipb;
		k->addr_b = *ipa;
		k->port_a = ptb;
		k->port_b = pta;
	}
}

#define ct_result_np_node(res)		((res).flags & CALI_CT_FLAG_NP_FWD)

static CALI_BPF_INLINE void dump_ct_key(struct cali_tc_ctx *ctx, struct calico_ct_key *k)
{
	CALI_VERB("CT-ALL   key A=" IP_FMT ":%d proto=%d", debug_ip(k->addr_a), k->port_a, (int)k->protocol);
	CALI_VERB("CT-ALL   key B=" IP_FMT ":%d size=%d", debug_ip(k->addr_b), k->port_b, (int)sizeof(struct calico_ct_key));
}

static CALI_BPF_INLINE int calico_ct_v4_create_tracking(struct cali_tc_ctx *ctx,
							struct ct_create_ctx *ct_ctx,
							struct calico_ct_key *k)
{
	__u16 sport = ct_ctx->sport;
	__u16 dport = ct_ctx->dport;
	__u16 orig_dport = ct_ctx->orig_dport;
	int err = 0;


	__be32 seq = 0;
	bool syn = false;
	__u64 now;

	if (ct_ctx->proto == IPPROTO_TCP) {
		seq = tcp_hdr(ctx)->seq;
		syn = tcp_hdr(ctx)->syn;
	}

	CALI_DEBUG("CT-ALL packet mark is: 0x%x", ctx->skb->mark);
	if (skb_seen(ctx->skb)) {
		/* Packet already marked as being from another workload, which will
		 * have created a conntrack entry.  Look that one up instead of
		 * creating one.
		 */
		CALI_VERB("CT-ALL Asked to create entry but packet is marked as "
				"from another endpoint, doing lookup");
		bool srcLTDest = src_lt_dest(&ct_ctx->src, &ct_ctx->dst, sport, dport);
		fill_ct_key(k, srcLTDest, ct_ctx->proto, &ct_ctx->src, &ct_ctx->dst, sport, dport);
		struct calico_ct_value *ct_value = cali_ct_lookup_elem(k);
		if (!ct_value) {
			CALI_VERB("CT Packet marked as from workload but got a conntrack miss!");
			goto create;
		}
		if (srcLTDest) {
			CALI_DEBUG("CT-ALL update src_to_dst A->B");
			ct_value->a_to_b.seqno = seq;
			ct_value->a_to_b.syn_seen = syn;
			if (CALI_F_TO_HOST) {
				ct_value->a_to_b.approved = 1;
				ct_value->a_to_b.workload = CALI_F_WEP ? 1 : 0;
			} else {
				ct_value->b_to_a.approved = 1;
				ct_value->b_to_a.workload = CALI_F_WEP ? 1 : 0;
			}
		} else  {
			CALI_DEBUG("CT-ALL update src_to_dst B->A");
			ct_value->b_to_a.seqno = seq;
			ct_value->b_to_a.syn_seen = syn;
			if (CALI_F_TO_HOST) {
				ct_value->b_to_a.approved = 1;
				ct_value->b_to_a.workload = CALI_F_WEP ? 1 : 0;
			} else {
				ct_value->a_to_b.approved = 1;
				ct_value->a_to_b.workload = CALI_F_WEP ? 1 : 0;
			}
		}

		return 0;
	}

create:
	now = bpf_ktime_get_ns();
	CALI_DEBUG("CT-ALL Creating tracking entry type %d at %llu.", ct_ctx->type, now);

	struct calico_ct_value ct_value = {
		.last_seen=now,
		.type = ct_ctx->type,
		.orig_ip = ct_ctx->orig_dst,
		.orig_port = orig_dport,
	};

	ct_value_set_flags(&ct_value, ct_ctx->flags);
	CALI_DEBUG("CT-ALL tracking entry flags 0x%x", ct_value_get_flags(&ct_value));

	ct_value.orig_sip = ct_ctx->orig_src;
	ct_value.orig_sport = ct_ctx->orig_sport;
	CALI_DEBUG("CT-ALL SNAT orig " IP_FMT ":%d", debug_ip(ct_ctx->orig_src),  ct_ctx->orig_sport);


	if (ct_ctx->type == CALI_CT_TYPE_NAT_REV && !ip_void(ct_ctx->tun_ip)) {
		if (ct_ctx->flags & CALI_CT_FLAG_NP_FWD) {
			CALI_DEBUG("CT-ALL nat tunneled to " IP_FMT "", debug_ip(ct_ctx->tun_ip));
		} else {
			struct cali_rt *rt = cali_rt_lookup(&ct_ctx->tun_ip);
			if (!rt || !cali_rt_is_host(rt)) {
				CALI_DEBUG("CT-ALL nat tunnel IP not a host " IP_FMT "", debug_ip(ct_ctx->tun_ip));
				err = -1;
				goto out;
			}
			CALI_DEBUG("CT-ALL nat tunneled from " IP_FMT "", debug_ip(ct_ctx->tun_ip));
		}
		ct_value.tun_ip = ct_ctx->tun_ip;
	}

	struct calico_ct_leg *src_to_dst, *dst_to_src;
	bool srcLTDest = src_lt_dest(&ct_ctx->src, &ct_ctx->dst, sport, dport);

	fill_ct_key(k, srcLTDest, ct_ctx->proto, &ct_ctx->src, &ct_ctx->dst, sport, dport);
	if (srcLTDest) {
		CALI_VERB("CT-ALL src_to_dst A->B");
		src_to_dst = &ct_value.a_to_b;
		dst_to_src = &ct_value.b_to_a;
	} else  {
		CALI_VERB("CT-ALL src_to_dst B->A");
		src_to_dst = &ct_value.b_to_a;
		dst_to_src = &ct_value.a_to_b;
		ct_value_set_flags(&ct_value, CALI_CT_FLAG_BA);
	}

	dump_ct_key(ctx, k);

	src_to_dst->seqno = seq;
	src_to_dst->syn_seen = syn;
	src_to_dst->opener = 1;
	src_to_dst->packets = 1;
	src_to_dst->bytes = ctx->skb->len;
	if (CALI_F_TO_HOST) {
		src_to_dst->ifindex = skb_ingress_ifindex(ctx->skb);
	} else {
		src_to_dst->ifindex = CT_INVALID_IFINDEX;
	}
	CALI_DEBUG("NEW src_to_dst->ifindex %d", src_to_dst->ifindex);
	dst_to_src->ifindex = CT_INVALID_IFINDEX;

	if (CALI_F_FROM_WEP) {
		/* src is the from the WEP, policy approved this side */
		src_to_dst->approved = 1;
		src_to_dst->workload = 1;
	} else if (CALI_F_FROM_HEP) {
		/* src is the from the HEP, policy approved this side */
		src_to_dst->approved = 1;

		if (ct_ctx->allow_return) {
			/* When we do NAT and forward through the tunnel, we go through
			 * a single policy, what we forward we also accept back,
			 * approve both sides.
			 */
			dst_to_src->approved = 1;
		}
		CALI_DEBUG("CT-ALL approved source side - from HEP tun allow_return=%d",
				ct_ctx->allow_return);
	} else if (CALI_F_TO_HEP && !skb_seen(ctx->skb) && (ct_ctx->type == CALI_CT_TYPE_NAT_REV)) {
		src_to_dst->approved = 1;
		dst_to_src->approved = 1;
		CALI_DEBUG("CT-ALL approved both due to host source port conflict resolution.");
	} else if (CALI_F_FROM_HOST) {
		if (ctx->state->flags & CALI_ST_CT_NP_LOOP) {
			/* we do not run policy and it should behave like TO_HOST */
			src_to_dst->approved = 1;
			CALI_DEBUG("CT-ALL approved source side - from HEP tun allow_return=%d",
					ct_ctx->allow_return);
		} else {
			/* dst is to the EP, policy approved this side */
			dst_to_src->approved = 1;
			CALI_DEBUG("CT-ALL approved dest side - to EP");
		}
	}

	err = cali_ct_update_elem(k, &ct_value, BPF_NOEXIST);

	if (CALI_F_HEP && err == -17 /* EEXIST */) {
		int i;

		CALI_DEBUG("Source collision for " IP_FMT ":%d", debug_ip(ct_ctx->src), sport);
		counter_inc(ctx, CALI_REASON_SOURCE_COLLISION);

		ct_value.orig_sport = sport;

		bool src_lt_dst = ip_lt(&ct_ctx->src, &ct_ctx->dst);

		for (i = 0; i < PSNAT_RETRIES; i++) {
			sport = psnat_get_port(ctx);
			CALI_DEBUG("New sport %d", sport);

			if (ip_equal(ct_ctx->src, ct_ctx->dst)) {
				src_lt_dst = sport < dport;
			}

			fill_ct_key(k, src_lt_dst, ct_ctx->proto, &ct_ctx->src, &ct_ctx->dst, sport, dport);

			if (!(err = cali_ct_update_elem(k, &ct_value, BPF_NOEXIST))) {
				ct_ctx->sport = sport;
				break;
			}
		}

		if (i == PSNAT_RETRIES) {
			CALI_INFO("Source collision unresolved " IP_FMT ":%d",
					debug_ip(ct_ctx->src), ct_value.orig_sport);
			err = -17; /* EEXIST */
			counter_inc(ctx, CALI_REASON_SOURCE_COLLISION_FAILED);
		}
	}

out:
	CALI_VERB("CT-ALL Create result: %d.", err);
	return err;
}

static CALI_BPF_INLINE int calico_ct_create_nat_fwd(struct cali_tc_ctx *ctx,
						    struct ct_create_ctx *ct_ctx,
						    struct calico_ct_key *rk)
{
	ipv46_addr_t ip_src = ct_ctx->orig_src;
	ipv46_addr_t ip_dst = ct_ctx->orig_dst;
	__u16 sport = ct_ctx->orig_sport;
	__u16 dport = ct_ctx->orig_dport;

	if (CALI_F_TO_HEP && !CALI_F_NAT_IF && sport != ct_ctx->sport &&
			!(ctx->skb->mark & (CALI_SKB_MARK_FROM_NAT_IFACE_OUT | CALI_SKB_MARK_SEEN))) {
		/* This entry is being created because we have a source port
		 * conflict on a connection from host. We did psnat so we mark
		 * such an entry with a 0 sport.
		 */
		sport = 0;
		CALI_DEBUG("FWD for psnat host conflict");
	}

	__u64 now = bpf_ktime_get_ns();

	CALI_DEBUG("CT-%d Creating FWD entry at %llu.", ct_ctx->proto, now);
	CALI_DEBUG("FWD " IP_FMT " -> " IP_FMT "", debug_ip(ip_src), debug_ip(ip_dst));
	struct calico_ct_value ct_value = {
		.type = CALI_CT_TYPE_NAT_FWD,
		.last_seen = now,
	};

	ct_value.nat_rev_key = *rk;

	/* We do not need rk anymore, we can reuse it for the new key.
	 *
	 * N.B. calico_ct_create_nat_fwd() is called _after_ calico_ct_v4_create_tracking()
	 * which also uses the rk!
	 */
	struct calico_ct_key *k = rk;
	bool srcLTDest = src_lt_dest(&ip_src, &ip_dst, sport, dport);
	fill_ct_key(k, srcLTDest, ct_ctx->proto, &ip_src, &ip_dst, sport, dport);

	if (ct_ctx->orig_sport != ct_ctx->sport) {
		ct_value.nat_sport = ct_ctx->sport;
	}
	int err = cali_ct_update_elem(k, &ct_value, 0);
	CALI_VERB("CT-%d Create result: %d.", ctx->state->ip_proto, err);
	return err;
}

#ifndef IPVER6
/* skb_icmp_err_unpack tries to unpack the inner IP and TCP/UDP header from an ICMP error message.
 * It updates the ct_ctx with the protocol/src/dst/ports of the inner packet.  If the unpack fails
 * (due to packet too short, for example), it returns false and sets the RC in the cali_tc_ctx to
 * TC_ACT_SHOT.
 */
static CALI_BPF_INLINE bool skb_icmp_err_unpack(struct cali_tc_ctx *ctx, struct ct_lookup_ctx *ct_ctx)
{
	/* ICMP packet is an error, its payload should contain the full IP header and
	 * at least the first 8 bytes of the next header. */

	int inner_ip_size;

	if (ctx->ipheader_len == 20) {
		if (skb_refresh_validate_ptrs(ctx, ICMP_SIZE + sizeof(struct iphdr) + 8)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			ctx->fwd.res = TC_ACT_SHOT;
			CALI_DEBUG("ICMP v4 reply: too short getting hdr");
			return false;
		}

		struct iphdr *ip_inner;
		ip_inner = (struct iphdr *)(ctx->data_start + skb_iphdr_offset(ctx) + IP_SIZE + ICMP_SIZE);
		CALI_DEBUG("CT-ICMP: proto %d", ip_inner->protocol);

		ct_ctx->proto = ip_inner->protocol;
		ct_ctx->src = ip_inner->saddr;
		ct_ctx->dst = ip_inner->daddr;

		if (ip_inner->ihl == 5) {
			switch (ip_inner->protocol) {
			case IPPROTO_TCP:
				{
					struct tcphdr *tcp = (struct tcphdr *)(ip_inner + 1);
					ct_ctx->sport = bpf_ntohs(tcp->source);
					ct_ctx->dport = bpf_ntohs(tcp->dest);
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
		} else {
			inner_ip_size = ip_inner->ihl * 4;
			/* fall through to obtaining l4 using bpf_skb_load_bytes */
		}
	} else {
		__u8 buf[IP_SIZE];
		if (bpf_skb_load_bytes(ctx->skb, skb_l4hdr_offset(ctx) + ICMP_SIZE, buf, IP_SIZE)) {
			CALI_DEBUG("ICMP v4 reply: too short getting ip hdr w/ options");
			return false;
		}
		ct_ctx->proto = ((struct iphdr*)buf)->protocol;
		ct_ctx->src = ((struct iphdr*)buf)->saddr;
		ct_ctx->dst = ((struct iphdr*)buf)->daddr;
		inner_ip_size = ((struct iphdr*)buf)->ihl * 4;
	}

	__u8 buf[8];

	if (bpf_skb_load_bytes(ctx->skb, skb_l4hdr_offset(ctx) + ICMP_SIZE + inner_ip_size, buf, 8)) {
		CALI_DEBUG("ICMP v4 reply: too short getting l4 hdr w/ options");
		return false;
	}

	switch (ct_ctx->proto) {
	case IPPROTO_TCP:
		ct_ctx->sport = bpf_ntohs(((struct tcphdr *)buf)->source);
		ct_ctx->dport = bpf_ntohs(((struct tcphdr *)buf)->dest);
		break;
	case IPPROTO_UDP:
		ct_ctx->sport = bpf_ntohs(((struct udphdr *)buf)->source);
		ct_ctx->dport = bpf_ntohs(((struct udphdr *)buf)->dest);
		break;
	};

	return true;
}

#else /* IPVER6 */

static CALI_BPF_INLINE bool skb_icmp6_err_unpack(struct cali_tc_ctx *ctx, struct ct_lookup_ctx *ct_ctx)
{
	__u8 buf[IP_SIZE];
	CALI_DEBUG("reading inner ipv6 at %d", skb_l4hdr_offset(ctx) + ICMP_SIZE);
	if (bpf_skb_load_bytes(ctx->skb, skb_l4hdr_offset(ctx) + ICMP_SIZE, buf, IP_SIZE)) {
		CALI_DEBUG("ICMP v6 reply: too short getting ip hdr w/ options");
		return false;
	}

	ipv6hdr_ip_to_ipv6_addr_t(&ct_ctx->src, &((struct ipv6hdr*)buf)->saddr);
	ipv6hdr_ip_to_ipv6_addr_t(&ct_ctx->dst, &((struct ipv6hdr*)buf)->daddr);

	int hdr = ((struct ipv6hdr*)buf)->nexthdr;
	int ipoff = skb_l4hdr_offset(ctx) + ICMP_SIZE;
	int len = IP_SIZE;

	CALI_DEBUG("ipv6 next hdr: %d", hdr);

	switch (hdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ct_ctx->proto = hdr;
		goto get_ports;
	case NEXTHDR_NONE:
		return false;
	}

	int i;

	for (i = 0; i < 8; i++) {
		struct ipv6_opt_hdr opt;

		CALI_DEBUG("loading extension at offset %d", ipoff + len);
		if (bpf_skb_load_bytes(ctx->skb, ipoff + len, &opt, sizeof(opt))) {
			CALI_DEBUG("Too short");
			return false;
		}

		CALI_DEBUG("ext nexthdr %d hdrlen %d", opt.nexthdr, opt.hdrlen);

		switch(hdr) {
		case NEXTHDR_FRAGMENT:
			len += 16;
			break;
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
		case NEXTHDR_GRE:
		case NEXTHDR_ESP:
		case NEXTHDR_AUTH:
		case NEXTHDR_MOBILITY:
			len += (opt.hdrlen + 1) * 8;
			break;
		}

		switch(opt.nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				ct_ctx->proto = opt.nexthdr;
				goto get_ports;
			case NEXTHDR_NONE:
				return false;
		}


	}

get_ports:

	if (bpf_skb_load_bytes(ctx->skb, ipoff + len, buf, 8)) {
		CALI_DEBUG("ICMP v6 reply: too short getting l4 hdr w/ options");
		return false;
	}

	switch (ct_ctx->proto) {
	case IPPROTO_TCP:
		ct_ctx->sport = bpf_ntohs(((struct tcphdr *)buf)->source);
		ct_ctx->dport = bpf_ntohs(((struct tcphdr *)buf)->dest);
		break;
	case IPPROTO_UDP:
		ct_ctx->sport = bpf_ntohs(((struct udphdr *)buf)->source);
		ct_ctx->dport = bpf_ntohs(((struct udphdr *)buf)->dest);
		break;
	};

	return true;
}

#endif /* IPVER6 */

#define CALI_CT_LOG(level, fmt, ...) \
	__CALI_LOG_IF(level, "CT: "fmt, ## __VA_ARGS__)
#define CALI_CT_DEBUG(fmt, ...) \
	CALI_CT_LOG(CALI_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define CALI_CT_VERB(fmt, ...) \
	CALI_CT_LOG(CALI_LOG_LEVEL_VERB, fmt, ## __VA_ARGS__)

#define seqno_add(seq, add) (bpf_htonl((bpf_ntohl(seq) + add)))

static CALI_BPF_INLINE void ct_tcp_entry_update(struct cali_tc_ctx *ctx,
						struct tcphdr *tcp_header,
						struct calico_ct_leg *src_to_dst,
						struct calico_ct_leg *dst_to_src)
{
	if (tcp_header->fin) {
		CALI_CT_VERB("FIN seen, marking CT entry.");
		src_to_dst->fin_seen = 1;
	}

	if (tcp_header->syn && tcp_header->ack) {
		if (dst_to_src->syn_seen && seqno_add(dst_to_src->seqno, 1) == tcp_header->ack_seq) {
			CALI_CT_VERB("SYN+ACK seen, marking CT entry.");
			src_to_dst->syn_seen = 1;
			src_to_dst->ack_seen = 1;
			src_to_dst->seqno = tcp_header->seq;
		} else {
			CALI_CT_VERB("SYN+ACK seen but packet's ACK (%u) "
					"doesn't match other side's SYN (%u).",
					bpf_ntohl(tcp_header->ack_seq),
					bpf_ntohl(dst_to_src->seqno));
			/* XXX Have to let this through so source can reset? */
		}
	} else if (tcp_header->ack && !src_to_dst->ack_seen && src_to_dst->syn_seen) {
		if (dst_to_src->syn_seen && seqno_add(dst_to_src->seqno, 1) == tcp_header->ack_seq) {
			CALI_CT_VERB("ACK seen, marking CT entry.");
			src_to_dst->ack_seen = 1;
		} else {
			CALI_CT_VERB("ACK seen but packet's ACK (%u) doesn't "
					"match other side's SYN (%u).",
					bpf_ntohl(tcp_header->ack_seq),
					bpf_ntohl(dst_to_src->seqno));
			/* XXX Have to let this through so source can reset? */
		}
	} else {
		/* Normal packet, check that the handshake is complete. */
		if (!dst_to_src->ack_seen) {
			CALI_CT_VERB("Non-flagged packet but other side has never ACKed.");
			/* XXX Have to let this through so source can reset? */
		} else if (src_to_dst->rst_seen | dst_to_src->rst_seen) {
			/* Remove the flag, we have seen traffic, but we still
			 * have the RST timestamp in case this is some residual
			 * traffic and the connection becomes silent.
			 */
			src_to_dst->rst_seen = dst_to_src->rst_seen = 0;
		} else {
			CALI_CT_VERB("Non-flagged packet and other side has ACKed.");
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

static CALI_BPF_INLINE struct calico_ct_result calico_ct_lookup(struct cali_tc_ctx *ctx)
{
	struct ct_lookup_ctx ct_lookup_ctx = {
		.proto	= STATE->ip_proto,
		.src	= STATE->ip_src,
		.sport	= STATE->sport,
		.dst	= STATE->ip_dst,
		.dport	= STATE->dport,
	};
	struct ct_lookup_ctx *ct_ctx = &ct_lookup_ctx;

	switch (STATE->ip_proto) {
	case IPPROTO_TCP:
		if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
			deny_reason(ctx, CALI_REASON_SHORT);
			CALI_DEBUG("Too short");
			bpf_exit(TC_ACT_SHOT);
		}
		ct_lookup_ctx.tcp = tcp_hdr(ctx);
		break;
	}

	__u8 proto_orig = STATE->ip_proto;
	struct tcphdr *tcp_header = STATE->ip_proto == IPPROTO_TCP ? tcp_hdr(ctx) : NULL;
	bool related = false;

	CALI_CT_DEBUG("lookup from " IP_FMT ":%d", debug_ip(STATE->ip_src), STATE->sport);
	CALI_CT_DEBUG("lookup to   " IP_FMT ":%d", debug_ip(STATE->ip_dst), STATE->dport);
	if (tcp_header) {
		CALI_CT_VERB("packet seq = %u", bpf_ntohl(tcp_header->seq));
		CALI_CT_VERB("packet ack_seq = %u", bpf_ntohl(tcp_header->ack_seq));
		CALI_CT_VERB("packet syn = %d", tcp_header->syn);
		CALI_CT_VERB("packet ack = %d", tcp_header->ack);
		CALI_CT_VERB("packet fin = %d", tcp_header->fin);
		CALI_CT_VERB("packet rst = %d", tcp_header->rst);
	}

	struct calico_ct_result result = {
		.rc = CALI_CT_NEW, /* it is zero, but make it explicit in the code */
		.ifindex_created = CT_INVALID_IFINDEX,
	};

	struct calico_ct_key k;
	bool syn = tcp_header && tcp_header->syn && !tcp_header->ack;

	if (ct_ctx->proto == IPPROTO_ICMP_46) {
		/* There are no ports in ICMP and the fields in state are overloaded
		 * for other use like type and code.
		 */
		ct_lookup_ctx.dport = 0;

#ifdef IPVER6
		if (icmp_type_is_err(icmp_hdr(ctx)->icmp6_type)) {
#else
		if (icmp_type_is_err(icmp_hdr(ctx)->type)) {
#endif
			/* ICMP error packets are a response to a failed UDP/TCP/etc
			 * packet.  Try to extract the details of the inner packet.
			 */
#ifdef IPVER6
			if (!skb_icmp6_err_unpack(ctx, ct_ctx)) {
#else
			if (!skb_icmp_err_unpack(ctx, ct_ctx)) {
#endif
					CALI_CT_DEBUG("Failed to parse ICMP error packet.");
					goto out_invalid;
			}

			/* skb_icmp_err_unpack updates the ct_ctx with the details of the inner packet;
			 * look for a conntrack entry for the inner packet...
			 */
			CALI_CT_DEBUG("related lookup from " IP_FMT ":%d", debug_ip(ct_ctx->src), ct_ctx->sport);
			CALI_CT_DEBUG("related lookup to   " IP_FMT ":%d", debug_ip(ct_ctx->dst), ct_ctx->dport);
			related = true;
			tcp_header = STATE->ip_proto == IPPROTO_TCP ? tcp_hdr(ctx) : NULL;


			/* We failed to look up the original flow, but it is an ICMP error and we
			 * _do_ have a CT entry for the packet inside the error.  ct_ctx has been
			 * updated to describe the inner packet.
			 */

			ctx->state->sport = ct_ctx->sport;
			ctx->state->dport = ct_ctx->dport;
		}
	}

	bool srcLTDest = src_lt_dest(&ct_ctx->src, &ct_ctx->dst, ct_ctx->sport, ct_ctx->dport);
	fill_ct_key(&k, srcLTDest, ct_ctx->proto, &ct_ctx->src, &ct_ctx->dst, ct_ctx->sport, ct_ctx->dport);

	struct calico_ct_value *v = cali_ct_lookup_elem(&k);
	if (!v) {
		if (syn) {
			// SYN packet (new flow); send it to policy.
			CALI_CT_DEBUG("Miss for TCP SYN, NEW flow.");
			goto out_lookup_fail;
		}
		if (CALI_F_FROM_HOST && proto_orig == IPPROTO_TCP) {
			// Mid-flow TCP packet with no conntrack entry leaving the host namespace.
			CALI_DEBUG("BPF CT Miss for mid-flow TCP");
			if ((ctx->skb->mark & CALI_SKB_MARK_CT_ESTABLISHED_MASK) == CALI_SKB_MARK_CT_ESTABLISHED) {
				// Linux Conntrack has marked the packet as part of an established flow.
				// TODO-HEP Create a tracking entry for uplifted flow so that we handle the reverse traffic more efficiently.
				 CALI_DEBUG("BPF CT Miss but have Linux CT entry: established");
				 result.rc = CALI_CT_ESTABLISHED;
				 return result;
			}
			CALI_DEBUG("BPF CT Miss but Linux CT entry not signalled");
			result.rc = CALI_CT_MID_FLOW_MISS;
			return result;
		}
		if (CALI_F_TO_HOST && proto_orig == IPPROTO_TCP) {
			// Miss for a mid-flow TCP packet towards the host.  This may be part of a
			// connection that predates the BPF program so we need to let it fall through
			// to iptables.
			CALI_DEBUG("BPF CT Miss for mid-flow TCP");
			result.rc = CALI_CT_MID_FLOW_MISS;
			return result;
		}
		CALI_CT_DEBUG("Miss.");
		if (related) {
			goto out_invalid;
		} else {
			goto out_lookup_fail;
		}
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
		CALI_CT_DEBUG("Hit! NAT FWD entry, doing secondary lookup.");
		tracking_v = cali_ct_lookup_elem(&v->nat_rev_key);
		if (!tracking_v) {
			CALI_CT_DEBUG("Miss when looking for secondary entry.");
			goto out_lookup_fail;
		}
		if (tcp_recycled(syn, tracking_v)) {
			CALI_CT_DEBUG("TCP SYN recycles entry, NEW flow.");
			cali_ct_delete_elem(&k);
			cali_ct_delete_elem(&v->nat_rev_key);
			goto out_lookup_fail;
		}

		// Record timestamp.
		tracking_v->last_seen = now;

		if (!(ct_value_get_flags(tracking_v) & CALI_CT_FLAG_BA)) {
			CALI_VERB("CT-ALL FWD-REV src_to_dst A->B");
			src_to_dst = &tracking_v->a_to_b;
			dst_to_src = &tracking_v->b_to_a;
			result.nat_ip = v->nat_rev_key.addr_b;
			result.nat_port = v->nat_rev_key.port_b;
			result.nat_sip = v->nat_rev_key.addr_a;
			result.nat_sport = v->nat_rev_key.port_a;
		} else {
			CALI_VERB("CT-ALL FWD-REV src_to_dst B->A");
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
		CALI_CT_DEBUG("fwd tun_ip:" IP_FMT "", debug_ip(tracking_v->tun_ip));
		// flags are in the tracking entry
		result.flags = ct_value_get_flags(tracking_v);
		CALI_CT_DEBUG("result.flags 0x%x", result.flags);

		if (ct_ctx->proto == IPPROTO_ICMP_46) {
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
			result.nat_ip = tracking_v->orig_ip;
		} else if (CALI_F_TO_HOST ||
				(CALI_F_TO_HEP && result.flags & (CALI_CT_FLAG_VIA_NAT_IF |
								  CALI_CT_FLAG_NP_LOOP |
								  CALI_CT_FLAG_NP_REMOTE))) {
			// Since we found a forward NAT entry, we know that it's the destination
			// that needs to be NATted.
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
		} else {
			result.rc =	CALI_CT_ESTABLISHED;
		}

		/* If we are on a HEP - where encap/decap can happen - and if the packet
		 * arrived through a tunnel, check if the src IP of the packet is expected.
		 */
		if (CALI_F_FROM_HEP && !ip_void(ctx->state->tun_ip) && !ip_void(result.tun_ip) &&
				!ip_equal(result.tun_ip, ctx->state->tun_ip)) {
			CALI_CT_DEBUG("tunnel src changed from " IP_FMT " to " IP_FMT "",
					debug_ip(result.tun_ip), debug_ip(ctx->state->tun_ip));
			ct_result_set_flag(result.rc, CT_RES_TUN_SRC_CHANGED);
		}

		if (tracking_v->a_to_b.approved && tracking_v->b_to_a.approved) {
			ct_result_set_flag(result.rc, CT_RES_CONFIRMED);
		}

		break;
	case CALI_CT_TYPE_NAT_REV:
		// N.B. we do not check for tcp_recycled because this cannot be the first
		// SYN that is opening a new connection. This must be returning traffic.
		if (srcLTDest) {
			CALI_VERB("CT-ALL REV src_to_dst A->B");
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			CALI_VERB("CT-ALL REV src_to_dst B->A");
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		result.tun_ip = v->tun_ip;
		CALI_CT_DEBUG("tun_ip:" IP_FMT "", debug_ip(v->tun_ip));

		result.flags = ct_value_get_flags(v);

		if (ct_ctx->proto == IPPROTO_ICMP_46 || (related && proto_orig == IPPROTO_ICMP_46)) {
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
		snat |= (dnat_return_should_encap() && !ip_void(v->tun_ip));
		snat |= result.flags & CALI_CT_FLAG_VIA_NAT_IF;
		snat |= result.flags & CALI_CT_FLAG_HOST_PSNAT;
		snat |= result.flags & CALI_CT_FLAG_NP_LOOP;
		snat |= result.flags & CALI_CT_FLAG_NP_REMOTE;
		snat = snat && dst_to_src->opener;

		if (snat) {
			CALI_CT_DEBUG("Hit! NAT REV entry at ingress to connection opener: SNAT.");
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_ip;
			result.nat_sip = v->orig_sip;
			result.nat_port = v->orig_port;
			result.nat_sport = v->orig_sport;
		} else {
			CALI_CT_DEBUG("Hit! NAT REV entry but not connection opener: ESTABLISHED.");
			result.rc =	CALI_CT_ESTABLISHED;
		}

		if (v->a_to_b.approved && v->b_to_a.approved) {
			ct_result_set_flag(result.rc, CT_RES_CONFIRMED);
		}

		break;

	case CALI_CT_TYPE_NORMAL:
		CALI_CT_DEBUG("Hit! NORMAL entry.");
		if (tcp_recycled(syn, v)) {
			CALI_CT_DEBUG("TCP SYN recycles entry, NEW flow.");
			cali_ct_delete_elem(&k);
			goto out_lookup_fail;
		}
		if (tcp_header) {
			CALI_CT_VERB("Last seen: %llu.", v->last_seen);
			CALI_CT_VERB("A-to-B: seqno %u.", bpf_ntohl(v->a_to_b.seqno));
			CALI_CT_VERB("A-to-B: syn_seen %d.", v->a_to_b.syn_seen);
			CALI_CT_VERB("A-to-B: ack_seen %d.", v->a_to_b.ack_seen);
			CALI_CT_VERB("A-to-B: fin_seen %d.", v->a_to_b.fin_seen);
			CALI_CT_VERB("A-to-B: rst_seen %d.", v->a_to_b.rst_seen);
		}
		CALI_CT_VERB("A: approved %d.", v->a_to_b.approved);
		if (tcp_header) {
			CALI_CT_VERB("B-to-A: seqno %u.", bpf_ntohl(v->b_to_a.seqno));
			CALI_CT_VERB("B-to-A: syn_seen %d.", v->b_to_a.syn_seen);
			CALI_CT_VERB("B-to-A: ack_seen %d.", v->b_to_a.ack_seen);
			CALI_CT_VERB("B-to-A: fin_seen %d.", v->b_to_a.fin_seen);
			CALI_CT_VERB("B-to-A: rst_seen %d.", v->b_to_a.rst_seen);
		}
		CALI_CT_VERB("B: approved %d.", v->b_to_a.approved);

		if (v->a_to_b.approved && v->b_to_a.approved) {
			result.rc = CALI_CT_ESTABLISHED_BYPASS;
			ct_result_set_flag(result.rc, CT_RES_CONFIRMED);
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
		CALI_CT_DEBUG("Hit! UNKNOWN entry type.");
		goto out_lookup_fail;
	}

	int ret_from_tun = CALI_F_FROM_HEP &&
				!ip_void(ctx->state->tun_ip) &&
				ct_result_rc(result.rc) == CALI_CT_ESTABLISHED_DNAT &&
				src_to_dst->approved &&
				result.flags & CALI_CT_FLAG_NP_FWD;

	if (related) {
		if (proto_orig == IPPROTO_ICMP_46 && v->type != CALI_CT_TYPE_NAT_FWD) {
			/* flip src/dst as ICMP related carries the original ip/l4 headers in
			 * opposite direction - it is a reaction on the original packet.
			 *
			 * CALI_CT_TYPE_NAT_FWD matches in opposite direction so
			 * all is ok already.
			 */
			struct calico_ct_leg *tmp;

			tmp = src_to_dst;
			src_to_dst = dst_to_src;
			dst_to_src = tmp;
		}
	}

	if (ret_from_tun) {
		CALI_DEBUG("Packet returned from tunnel " IP_FMT "", debug_ip(ctx->state->tun_ip));
	} else if (CALI_F_TO_HOST || (skb_from_host(ctx->skb) && result.flags & CALI_CT_FLAG_HOST_PSNAT)) {
		/* Source of the packet is the endpoint, so check the src approval flag. */
		if (CALI_F_LO || src_to_dst->approved || (related && dst_to_src->approved)) {
			CALI_CT_VERB("Packet approved by this workload's policy.");
		} else {
			/* Only approved by the other side (so far)?  Unlike
			 * TCP we have no way to distinguish packets that open a
			 * new connection so we have to return NEW here in order
			 * to invoke policy.
			 */
			CALI_CT_DEBUG("Packet not allowed by ingress/egress approval flags (TH).");
			result.rc = tcp_header ? CALI_CT_INVALID : CALI_CT_NEW;
		}
	} else if (CALI_F_FROM_HOST) {
		/* Dest of the packet is the endpoint, so check the dest approval flag. */
		if (CALI_F_LO || dst_to_src->approved || (related && src_to_dst->approved)) {
			// Packet was approved by the policy attached to this endpoint.
			CALI_CT_VERB("Packet approved by this workload's policy.");
		} else {
			/* Only approved by the other side (so far)?  Unlike
			 * TCP we have no way to distinguish packets that open a
			 * new connection so we have to return NEW here in order
			 * to invoke policy.
			 */
			CALI_CT_DEBUG("Packet not allowed by ingress/egress approval flags (FH).");
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
		if (tcp_header->rst) {
			CALI_CT_DEBUG("RST seen, marking CT entry.");
			src_to_dst->rst_seen = 1;
			v->rst_seen = now;
		} else if (v->rst_seen) {
			if (now - v->rst_seen > 2 * 60 * 1000000000ull || now - v->rst_seen > (1ull << 63)) {
				/* It's been a looong time (2m) since we saw the RST, we still see
				 * traffic, we must have seen traffic between now and rst_seen,
				 * otherwise the entry would have been GCed, the connection is
				 * likely established and the RST was spurious.
				 */
				v->rst_seen = 0;
			}
		}
		ct_tcp_entry_update(ctx, tcp_header, src_to_dst, dst_to_src);
	}

	__u32 ifindex = skb_ingress_ifindex(ctx->skb);

	if (src_to_dst->ifindex != ifindex) {
		// Conntrack entry records a different ingress interface than the one the
		// packet arrived on (or it has no record yet).
		if (CALI_F_TO_HOST) {
			bool same_if = false;
			// Packet is towards the host so this program is the first to see the packet.
			if (src_to_dst->ifindex == CT_INVALID_IFINDEX) {
				// Conntrack entry has no record of the ingress interface, this should
				// be a response packet but we can't be 100% sure.
				CALI_CT_DEBUG("First response packet? ifindex=%d", ifindex);
				/* Check if the return packet follow the same path as the request. */
				same_if = dst_to_src->ifindex == ifindex;
			} else {
				// The interface has changed; either a change to routing or someone's doing
				// something nasty.
				CALI_CT_DEBUG("CT RPF failed ifindex %d != %d",
						src_to_dst->ifindex, ifindex);
			}

			int rpf_passed = RPF_RES_FAIL;
			if (same_if || ret_from_tun || CALI_F_NAT_IF || CALI_F_LO) {
				/* Do not worry about packets returning from the same direction as
				 * the outgoing packets.
				 *
				 * Do not check if packets are returning from the NP vxlan tunnel.
				 */
				rpf_passed = RPF_RES_STRICT;
			} else if (CALI_F_HEP) {
				rpf_passed = hep_rpf_check(ctx);
			} else {
				rpf_passed = wep_rpf_check(ctx, cali_rt_lookup(&ctx->state->ip_src));
			}

			switch (rpf_passed) {
			case RPF_RES_FAIL:
				ct_result_set_flag(result.rc, CT_RES_RPF_FAILED);
				src_to_dst->ifindex = CT_INVALID_IFINDEX;
				CALI_CT_DEBUG("CT RPF failed invalidating ifindex");
				break;
			case RPF_RES_STRICT:
				if (!related) {
					CALI_CT_DEBUG("Updating ifindex from %d to %d",
							src_to_dst->ifindex, ifindex);
					src_to_dst->ifindex = ifindex;
				}
				break;
			case RPF_RES_DISABLED:
			case RPF_RES_LOOSE:
				if (!related) {
					CALI_CT_DEBUG("Packet from unexpected ingress dev - rpf loose or disabled "
							"- reset ifindex", src_to_dst->ifindex, ifindex);
					src_to_dst->ifindex = CT_INVALID_IFINDEX;
				}
				break;
			}
		} else if (src_to_dst->ifindex != CT_INVALID_IFINDEX) {
			/* if the devices do not match, we got here without bypassing the
			 * host IP stack and RPF check allowed it, so update our records.
			 */
			CALI_CT_DEBUG("Updating ifindex from %d to %d",
					src_to_dst->ifindex, ifindex);
			src_to_dst->ifindex = ifindex;
		}
	}

	if (CALI_F_TO_HOST) {
		/* Fill in the ifindex we recorded in the opposite direction. The caller
		 * may use it to directly forward the packet to the same interface where
		 * packets in the opposite direction are coming from.
		 */
		result.ifindex_fwd = dst_to_src->ifindex;
		if (dst_to_src->workload) {
			ct_result_set_flag(result.rc, CT_RES_TO_WORKLOAD);
		}
	}

	if ((CALI_F_INGRESS && CALI_F_TUNNEL) || !skb_seen(ctx->skb)) {
		/* Account for the src->dst leg if we haven't seen the packet yet.
		 * Since when the traffic is tunneled, BPF program on the host
		 * iface sees it first and marks it as seen before another
		 * program sees the packet as decaped. Only then we can account
		 * for the bytes and packets. Unfortunately, we need to mark the
		 * packets as seen otherwise they would get dropped as something
		 * we missed.
		 *
		 * Needs to be done for tunnels that preserve the packet, like
		 * IPIP and unlike wireguard.
		 */
		src_to_dst->packets++;
		src_to_dst->bytes += ctx->skb->len;
	}

	if (syn) {
		CALI_CT_DEBUG("packet is SYN");
		ct_result_set_flag(result.rc, CT_RES_SYN);
	}


	CALI_CT_DEBUG("result: 0x%x", result.rc);

	if (related) {
		ct_result_set_flag(result.rc, CT_RES_RELATED);
		CALI_CT_DEBUG("result: related");
	}

	return result;

out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_CT_DEBUG("result: NEW.");
	return result;
out_invalid:
	result.rc = CALI_CT_INVALID;
	CALI_CT_DEBUG("result: INVALID.");
	return result;
}

/* creates connection tracking for tracked protocols */
static CALI_BPF_INLINE int conntrack_create(struct cali_tc_ctx *ctx, struct ct_create_ctx *ct_ctx)
{
	struct calico_ct_key *k = &ctx->scratch->ct_key;
	int err;

	if (ct_ctx->proto == IPPROTO_ICMP_46) {
		ct_ctx->dport = 0;
	}

	if (ctx->state->flags & CALI_ST_SUPPRESS_CT_STATE) {
		// CT state creation is suppressed.
		return 0;
	}

	err = calico_ct_v4_create_tracking(ctx, ct_ctx, k);
	if (err) {
		CALI_DEBUG("calico_ct_v4_create_tracking err %d", err);
		return err;
	}

	if (ct_ctx->type == CALI_CT_TYPE_NAT_REV) {
		err = calico_ct_create_nat_fwd(ctx, ct_ctx, k);
		if (err) {
			/* XXX we should clean up the tracking entry */
		}
	}

	return err;
}

#endif /* __CALI_CONNTRACK_H__ */
