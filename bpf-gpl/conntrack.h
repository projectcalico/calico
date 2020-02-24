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

// Connection tracking.

struct calico_ct_key {
	uint32_t protocol;
	__be32 addr_a, addr_b; // NBO
	uint16_t port_a, port_b; // HBO
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

struct calico_ct_leg {
	__u32 seqno;

	__u32 syn_seen:1;
	__u32 ack_seen:1;
	__u32 fin_seen:1;
	__u32 rst_seen:1;

	__u32 whitelisted:1;

	__u32 opener:1;
};

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
			struct calico_ct_leg b_to_a; // 32

			// CALI_CT_TYPE_NAT_REV
			__u32 orig_ip;                     // 40
			__u16 orig_port;                   // 44
			__u8 pad1[2];                      // 46
			__u32 tun_ip;                      // 48
			__u32 pad3;                        // 52
		};

		// CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
		struct {
			struct calico_ct_key nat_rev_key;  // 24
			__u8 pad2[8];
		};
	};
};

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
	__be32 nat_tun_src;
	__u8 flags;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_ct = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_ct_key),
	.value_size = sizeof(struct calico_ct_value),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 512000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2, /* global namespace */
#endif
};

static CALI_BPF_INLINE void dump_ct_key(struct calico_ct_key *k)
{
	CALI_VERB("CT-ALL   key A=%x:%d proto=%d\n", be32_to_host(k->addr_a), k->port_a, (int)k->protocol);
	CALI_VERB("CT-ALL   key B=%x:%d size=%d\n", be32_to_host(k->addr_b), k->port_b, (int)sizeof(struct calico_ct_key));
}

static CALI_BPF_INLINE int calico_ct_v4_create_tracking(struct ct_ctx *ctx,
							struct calico_ct_key *k,
							enum cali_ct_type type)
{
	__be32 ip_src = ctx->src;
	__be32 ip_dst = ctx->dst;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->dport;
	__be32 orig_dst = ctx->orig_dst;
	__u16 orig_dport = ctx->orig_dport;


	__be32 seq = 0;
	bool syn = false;
	__u64 now;

	if (ctx->tcp) {
		seq = ctx->tcp->seq;
		syn = ctx->tcp->syn;
	}

	if ((ctx->skb->mark & CALI_SKB_MARK_SEEN_MASK) == CALI_SKB_MARK_SEEN) {
		/* Packet already marked as being from another workload, which will
		 * have created a conntrack entry.  Look that one up instead of
		 * creating one.
		 */
		CALI_DEBUG("CT-ALL Asked to create entry but packet is marked as "
				"from another endpoint, doing lookup\n");
		bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
		if (srcLTDest) {
			*k = (struct calico_ct_key) {
				.protocol = ctx->proto,
				.addr_a = ip_src, .port_a = sport,
				.addr_b = ip_dst, .port_b = dport,
			};
		} else  {
			*k = (struct calico_ct_key) {
				.protocol = ctx->proto,
				.addr_a = ip_dst, .port_a = dport,
				.addr_b = ip_src, .port_b = sport,
			};
		}
		dump_ct_key(k);
		struct calico_ct_value *ct_value = bpf_map_lookup_elem(&cali_v4_ct, k);
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

	if (type == CALI_CT_TYPE_NAT_REV && ctx->nat_tun_src) {
		ct_value.tun_ip = ctx->nat_tun_src;
		CALI_DEBUG("CT-ALL nat tunneled from %x\n", be32_to_host(ctx->nat_tun_src));
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

	src_to_dst->seqno = seq;
	src_to_dst->syn_seen = syn;
	src_to_dst->opener = 1;

	int src_wl;

	/* whitelist src if from workload */
	src_wl = CALI_F_TO_HOST;
	/* whitelist src if DNAT + tunnel on host ingress -> will be forwarded */
	src_wl |= CALI_F_FROM_HEP && ctx->nat_tun_src;

	if (src_wl) {
		src_to_dst->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted source side\n");
	} else {
		dst_to_src->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted dest side\n");
	}
	int err = bpf_map_update_elem(&cali_v4_ct, k, &ct_value, 0);
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
	int err = bpf_map_update_elem(&cali_v4_ct, &k, &ct_value, 0);
	CALI_VERB("CT-%d Create result: %d.\n", ip_proto, err);
	return err;
}

static CALI_BPF_INLINE int calico_ct_v4_create(struct ct_ctx *ctx)
{
	struct calico_ct_key k;

	return calico_ct_v4_create_tracking(ctx, &k, CALI_CT_TYPE_NORMAL);
}

static CALI_BPF_INLINE int calico_ct_v4_create_nat(struct ct_ctx *ctx)
{
	struct calico_ct_key k;

	calico_ct_v4_create_tracking(ctx, &k, CALI_CT_TYPE_NAT_REV);
	calico_ct_v4_create_nat_fwd(ctx, &k);

	return 0;
}

enum calico_ct_result_type {
	CALI_CT_NEW,
	CALI_CT_ESTABLISHED,
	CALI_CT_ESTABLISHED_BYPASS,
	CALI_CT_ESTABLISHED_SNAT,
	CALI_CT_ESTABLISHED_DNAT,
	CALI_CT_INVALID,
};

struct calico_ct_result {
	__s16 rc;
	__u16 flags;
	__be32 nat_ip;
	__u32 nat_port;
	__be32 tun_ret_ip;
};

static CALI_BPF_INLINE void calico_ct_v4_tcp_delete(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport)
{
	CALI_DEBUG("CT-TCP delete from %x:%d\n", be32_to_host(ip_src), sport);
	CALI_DEBUG("CT-TCP delete to   %x:%d\n", be32_to_host(ip_dst), dport);

	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	struct calico_ct_key k;
	if (srcLTDest) {
		k = (struct calico_ct_key) {
			.protocol = IPPROTO_TCP,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
	} else  {
		k = (struct calico_ct_key) {
			.protocol = IPPROTO_TCP,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
	}

	dump_ct_key(&k);

	int rc = bpf_map_delete_elem(&cali_v4_ct, &k);
	CALI_DEBUG("CT-TCP delete result: %d\n", rc);
}

#define CALI_CT_LOG(level, fmt, ...) \
	CALI_LOG_IF_FLAG(level, CALI_COMPILE_FLAGS, "CT-%d "fmt, proto, ## __VA_ARGS__)
#define CALI_CT_DEBUG(fmt, ...) \
	CALI_CT_LOG(CALI_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define CALI_CT_VERB(fmt, ...) \
	CALI_CT_LOG(CALI_LOG_LEVEL_VERB, fmt, ## __VA_ARGS__)

#define seqno_add(seq, add) (host_to_be32((be32_to_host(seq) + add)))

static CALI_BPF_INLINE void ct_tcp_entry_update(struct tcphdr *tcp_header,
						struct calico_ct_leg *src_to_dst,
						struct calico_ct_leg *dst_to_src)
{
	__u8 proto = IPPROTO_TCP; /* used by logging */

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
	__u8 proto = ctx->proto;
	__be32 ip_src = ctx->src;
	__be32 ip_dst = ctx->dst;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->dport;
	struct tcphdr *tcp_header = ctx->tcp;

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

	struct calico_ct_result result = {};

	if (tcp_header && tcp_header->syn && !tcp_header->ack) {
		// SYN should always go through policy.
		CALI_CT_DEBUG("Packet is a SYN, short-circuiting lookup.\n");
		goto out_lookup_fail;
	}

	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	struct calico_ct_key k;
	if (srcLTDest) {
		k = (struct calico_ct_key) {
			.protocol = proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
	} else  {
		k = (struct calico_ct_key) {
			.protocol = proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
	}
	dump_ct_key(&k);

	struct calico_ct_value *v = bpf_map_lookup_elem(&cali_v4_ct, &k);
	if (!v) {
		CALI_CT_DEBUG("Miss.\n");
		goto out_lookup_fail;
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
		tracking_v = bpf_map_lookup_elem(&cali_v4_ct, &v->nat_rev_key);
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
		result.tun_ret_ip = tracking_v->tun_ip;
		CALI_CT_DEBUG("fwd tun_ip:%x\n", be32_to_host(tracking_v->tun_ip));

		if (proto == IPPROTO_ICMP) {
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
			result.nat_ip = tracking_v->orig_ip;
		} else if (CALI_F_TO_HOST) {
			// Since we found a forward NAT entry, we know that it's the destination
			// that needs to be NATted.
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
		} else {
			result.rc =	CALI_CT_ESTABLISHED;
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

		if (proto == IPPROTO_ICMP) {
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_ip;
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
		snat = !CALI_F_TO_HOST;
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
		result.tun_ret_ip = v->tun_ip;
		CALI_CT_DEBUG("tun_ip:%x\n", be32_to_host(v->tun_ip));
		break;

	case CALI_CT_TYPE_NORMAL:
		if (v->type == CALI_CT_TYPE_NORMAL) {
			CALI_CT_DEBUG("Hit! NORMAL entry.\n");
		}
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
				ctx->nat_tun_src &&
				result.rc == CALI_CT_ESTABLISHED_DNAT &&
				src_to_dst->whitelisted &&
				!result.tun_ret_ip;

	if (CALI_F_TO_HOST && !ctx->nat_tun_src) {
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
	} else if (ret_from_tun) {
		CALI_DEBUG("Packet returned from tunnel %x\n", be32_to_host(ctx->nat_tun_src));
	} else {
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

	if (tcp_header) {
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

	CALI_CT_DEBUG("result: %d.\n", result.rc);
	return result;

out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_CT_DEBUG("result: NEW.\n");
	return result;
}

/* creates connection tracking for tracked protocols */
static CALI_BPF_INLINE int conntrack_create(struct ct_ctx * ctx, bool nat)
{
	switch (ctx->proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		return nat ? calico_ct_v4_create_nat(ctx) : calico_ct_v4_create(ctx);
	default:
		return 0;
	}
}

#endif /* __CALI_CONNTRACK_H__ */
