#ifndef __CALI_CONNTRACK_H__
#define __CALI_CONNTRACK_H__

#include <linux/in.h>
#import "bpf.h"

// Connection tracking.

struct calico_ct_key {
	uint32_t protocol;
	__be32 addr_a, addr_b; // NBO
	uint16_t port_a, port_b; // HBO
};

enum CALI_CT_TYPE {
	CALI_CT_TYPE_NORMAL = 0,  // Non-NATted entry.
	CALI_CT_TYPE_NAT_FWD = 1, // Forward entry for a DNATted flow, keyed on orig src/dst. Points to the reverse entry.
	CALI_CT_TYPE_NAT_REV = 2, // "Reverse" entry for a NATted flow, contains NAT + tracking information.
};

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
	__u64 last_seen;
	__u8 type;

	// Important to use explicit padding, otherwise the compiler can decide
	// not to zero the padding bytes, which upsets the verifier.  Worse than
	// that, debug logging often prevents such optimisation resulting in
	// failures when debug logging is compiled out only :-).
	__u8 pad0[7];
	union {
		// CALI_CT_TYPE_NORMAL and CALI_CT_TYPE_NAT_REV.
		struct {
			struct calico_ct_leg a_to_b; // 8
			struct calico_ct_leg b_to_a; // 16

			// CALI_CT_TYPE_NAT_REV only.
			__u32 orig_dst;                    // 20
			__u16 orig_port;                   // 22
			__u8 pad1[2];                      // 24
		};

		// CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
		struct {
			struct calico_ct_key nat_rev_key;  // 16
			__u8 pad2[8];                      // 24
		};
	};
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_ct_map_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_ct_key),
	.value_size = sizeof(struct calico_ct_value),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 512000, // arbitrary
	.pinning_strategy = 2 /* global namespace */,
};

static CALI_BPF_INLINE void dump_ct_key(struct calico_ct_key *k, enum calico_tc_flags flags) {
	CALI_VERB("CT-TCP   key A=%x:%d proto=%d\n", be32_to_host(k->addr_a), k->port_a, (int)k->protocol);
	CALI_VERB("CT-TCP   key B=%x:%d size=%d\n", be32_to_host(k->addr_b), k->port_b, (int)sizeof(struct calico_ct_key));
}

static CALI_BPF_INLINE int calico_ct_v4_create_tracking(
		struct __sk_buff *skb,
		__u8 ip_proto,
		struct calico_ct_key *k, enum CALI_CT_TYPE type,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		__be32 orig_dst, __u16 orig_dport,
		__be32 seq, bool syn, enum calico_tc_flags flags) {

	if ((skb->mark & CALI_SKB_MARK_SEEN_MASK) == CALI_SKB_MARK_SEEN) {
		// Packet already marked as being from another workload, which will
		// have created a conntrack entry.  Look that one up instead of
		// creating one.
		CALI_DEBUG("CT-ALL Asked to create entry but packet is marked as "
				"from another endpoint, doing lookup\n");
		bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
		if (srcLTDest) {
			*k = (struct calico_ct_key) {
				.protocol = ip_proto,
				.addr_a = ip_src, .port_a = sport,
				.addr_b = ip_dst, .port_b = dport,
			};
		} else  {
			*k = (struct calico_ct_key) {
				.protocol = ip_proto,
				.addr_a = ip_dst, .port_a = dport,
				.addr_b = ip_src, .port_b = sport,
			};
		}
		dump_ct_key(k, flags);
		struct calico_ct_value *ct_value = bpf_map_lookup_elem(&calico_ct_map_v4, k);
		if (!ct_value) {
			CALI_VERB("CT Packet marked as from workload but got a conntrack miss!\n");
			goto create;
		}
		CALI_VERB("CT Found expected entry, updating...\n");
		if (srcLTDest) {
			ct_value->a_to_b.seqno = seq;
			ct_value->a_to_b.syn_seen = syn;
			if (CALI_TC_FLAGS_TO_HOST(flags)) {
				ct_value->a_to_b.whitelisted = 1;
			} else {
				ct_value->b_to_a.whitelisted = 1;
			}
		} else  {
			ct_value->b_to_a.seqno = seq;
			ct_value->b_to_a.syn_seen = syn;
			if (CALI_TC_FLAGS_TO_HOST(flags)) {
				ct_value->b_to_a.whitelisted = 1;
			} else {
				ct_value->a_to_b.whitelisted = 1;
			}
		}

		return 0;
	}

	__u64 now;
	create:
	now = bpf_ktime_get_ns();
	CALI_DEBUG("CT-ALL Creating entry at %llu.\n", now);
	struct calico_ct_value ct_value = {};
	ct_value.created=now;
	ct_value.last_seen=now;
	ct_value.type = type;
	ct_value.orig_dst = orig_dst;
	ct_value.orig_port = orig_dport;
	struct calico_ct_leg *src_to_dst, *dst_to_src;
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	if (srcLTDest) {
		*k = (struct calico_ct_key) {
			.protocol = ip_proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		src_to_dst = &ct_value.a_to_b;
		dst_to_src = &ct_value.b_to_a;
	} else  {
		*k = (struct calico_ct_key) {
			.protocol = ip_proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		src_to_dst = &ct_value.b_to_a;
		dst_to_src = &ct_value.a_to_b;
	}

	dump_ct_key(k, flags);

	src_to_dst->seqno = seq;
	src_to_dst->syn_seen = syn;
	src_to_dst->opener = 1;
	if (CALI_TC_FLAGS_TO_HOST(flags)) {
		src_to_dst->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted source side\n");
	} else {
		dst_to_src->whitelisted = 1;
		CALI_DEBUG("CT-ALL Whitelisted dest side\n");
	}
	int err = bpf_map_update_elem(&calico_ct_map_v4, k, &ct_value, 0);
	CALI_VERB("CT-ALL Create result: %d.\n", err);
	return err;
}

static CALI_BPF_INLINE int calico_ct_v4_create_nat_fwd(
		__u8 ip_proto,
		struct calico_ct_key *rk, __be32 ip_src,
		__be32 ip_dst, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
	__u64 now = bpf_ktime_get_ns();
	CALI_DEBUG("CT-TCP Creating entry at %llu.\n", now);
	struct calico_ct_value ct_value = {
		.type = CALI_CT_TYPE_NAT_FWD,
		.last_seen = now,
		.created = now,
	};
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	if (srcLTDest) {
		struct calico_ct_key k = {
			.protocol = ip_proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		dump_ct_key(&k, flags);
		ct_value.nat_rev_key = *rk;
		int err = bpf_map_update_elem(&calico_ct_map_v4, &k, &ct_value, 0);
		CALI_VERB("CT-TCP Create result: %d.\n", err);
		return err;
	} else  {
		struct calico_ct_key k = {
			.protocol = ip_proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		dump_ct_key(&k, flags);
		ct_value.nat_rev_key = *rk;
		int err = bpf_map_update_elem(&calico_ct_map_v4, &k, &ct_value, 0);
		CALI_VERB("CT-TCP Create result: %d.\n", err);
		return err;
	}
}

static CALI_BPF_INLINE int calico_ct_v4_tcp_create(
		struct __sk_buff *skb,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		struct tcphdr *tcp_header, enum calico_tc_flags flags) {
	struct calico_ct_key k;
	return calico_ct_v4_create_tracking(skb,
			IPPROTO_TCP, &k, CALI_CT_TYPE_NORMAL,
			ip_src, ip_dst, sport, dport, 0, 0,
			tcp_header->seq, tcp_header->syn, flags);
}

static CALI_BPF_INLINE int calico_ct_v4_udp_create(
		struct __sk_buff *skb,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	return calico_ct_v4_create_tracking(skb,
			IPPROTO_UDP, &k, CALI_CT_TYPE_NORMAL,
			ip_src, ip_dst, sport, dport, 0, 0, 0, 0, flags);
}

static CALI_BPF_INLINE int calico_ct_v4_icmp_create(
		struct __sk_buff *skb,
		__be32 ip_src, __be32 ip_dst,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	return calico_ct_v4_create_tracking(skb,
			IPPROTO_ICMP, &k, CALI_CT_TYPE_NORMAL,
			ip_src, ip_dst, 0, 0, 0, 0, 0, 0, flags);
}

static CALI_BPF_INLINE int calico_ct_v4_tcp_create_nat(
		struct __sk_buff *skb,
		__be32 orig_src, __be32 orig_dst, __u16 orig_sport, __u16 orig_dport,
		__be32 nat_dst, __u16 nat_dport, struct tcphdr *tcp_header,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	calico_ct_v4_create_tracking(skb,
			IPPROTO_TCP, &k, CALI_CT_TYPE_NAT_REV, orig_src,
			nat_dst, orig_sport, nat_dport, orig_dst, orig_dport,
			tcp_header->seq, tcp_header->syn, flags);
	calico_ct_v4_create_nat_fwd(IPPROTO_TCP, &k, orig_src, orig_dst, orig_sport,
			orig_dport, flags);
	return 0;
}

static CALI_BPF_INLINE int calico_ct_v4_udp_create_nat(
		struct __sk_buff *skb,
		__be32 orig_src, __be32 orig_dst, __u16 orig_sport, __u16 orig_dport,
		__be32 nat_dst, __u16 nat_dport,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	calico_ct_v4_create_tracking(skb,
			IPPROTO_UDP, &k, CALI_CT_TYPE_NAT_REV, orig_src,
			nat_dst, orig_sport, nat_dport, orig_dst, orig_dport,
			0, 0, flags);
	calico_ct_v4_create_nat_fwd(IPPROTO_UDP, &k, orig_src, orig_dst, orig_sport,
			orig_dport, flags);
	return 0;
}

static CALI_BPF_INLINE int calico_ct_v4_icmp_create_nat(
		struct __sk_buff *skb,
		__be32 orig_src, __be32 orig_dst,
		__be32 nat_dst,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	calico_ct_v4_create_tracking(skb,
			IPPROTO_ICMP, &k, CALI_CT_TYPE_NAT_REV, orig_src,
			nat_dst, 0, 0, orig_dst, 0, 0, 0, flags);
	calico_ct_v4_create_nat_fwd(IPPROTO_ICMP, &k, orig_src, orig_dst, 0, 0, flags);
	return 0;
}

enum calico_ct_result_type {
	CALI_CT_NEW,
	CALI_CT_ESTABLISHED,
	CALI_CT_ESTABLISHED_SNAT,
	CALI_CT_ESTABLISHED_DNAT,
	CALI_CT_INVALID,
};

struct calico_ct_result {
	enum calico_ct_result_type rc;

	// For CALI_CT_ESTABLISHED_SNAT and CALI_CT_ESTABLISHED_DNAT.
	__be32 nat_ip;
	__u32 nat_port;
};

static CALI_BPF_INLINE void calico_ct_v4_tcp_delete(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		enum calico_tc_flags flags) {
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

	dump_ct_key(&k, flags);

	int rc = bpf_map_delete_elem(&calico_ct_map_v4, &k);
	CALI_DEBUG("CT-TCP delete result: %d\n", rc);
}

static CALI_BPF_INLINE struct calico_ct_result calico_ct_v4_tcp_lookup(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		struct tcphdr *tcp_header, enum calico_tc_flags flags) {

	CALI_DEBUG("CT-TCP lookup from %x:%d\n", be32_to_host(ip_src), sport);
	CALI_DEBUG("CT-TCP lookup to   %x:%d\n", be32_to_host(ip_dst), dport);
	CALI_VERB("CT-TCP   packet seq = %u\n", tcp_header->seq);
	CALI_VERB("CT-TCP   packet ack_seq = %u\n", tcp_header->ack_seq);
	CALI_VERB("CT-TCP   packet syn = %d\n", tcp_header->syn);
	CALI_VERB("CT-TCP   packet ack = %d\n", tcp_header->ack);
	CALI_VERB("CT-TCP   packet fin = %d\n", tcp_header->fin);
	CALI_VERB("CT-TCP   packet rst = %d\n", tcp_header->rst);

	struct calico_ct_result result = {};

	if (tcp_header->syn && !tcp_header->ack) {
		// SYN should always go through policy.
		CALI_DEBUG("CT-TCP Packet is a SYN, short-circuiting lookup.\n");
		goto out_lookup_fail;
	}

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
	dump_ct_key(&k, flags);

	struct calico_ct_value *v = bpf_map_lookup_elem(&calico_ct_map_v4, &k);
	if (!v) {
		CALI_DEBUG("CT-TCP Miss.\n");
		goto out_lookup_fail;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	struct calico_ct_leg *src_to_dst, *dst_to_src;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALI_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALI_DEBUG("CT-TCP Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			CALI_DEBUG("CT-TCP Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			src_to_dst = &tracking_v->a_to_b;
			dst_to_src = &tracking_v->b_to_a;
			result.nat_ip = v->nat_rev_key.addr_b;
			result.nat_port = v->nat_rev_key.port_b;
		} else {
			src_to_dst = &tracking_v->b_to_a;
			dst_to_src = &tracking_v->a_to_b;
			result.nat_ip = v->nat_rev_key.addr_a;
			result.nat_port = v->nat_rev_key.port_a;
		}

		if (CALI_TC_FLAGS_TO_HOST(flags)) {
			// Since we found a forward NAT entry, we know that it's the destination
			// that needs to be NATted.
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
		} else {
			result.rc =	CALI_CT_ESTABLISHED;
		}
		break;
	case CALI_CT_TYPE_NAT_REV:
		// A reverse NAT entry; this means that the conntrack entry was keyed on the post-NAT
		// IPs.  We'll only ever see a NAT entry if the NAT happened on this host.  However,
		// if the source and destination of the traffic are on the same host then we'll end up here
		// in both the source workload's ingress hook and the destination workload's ingress hook.

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		if (!CALI_TC_FLAGS_TO_HOST(flags) && dst_to_src->opener) {
			// Packet is heading away from the host namespace; either entering a workload or
			// leaving via a host endpoint, actually reverse the NAT.
			CALI_DEBUG("CT-TCP Hit! NAT REV entry at ingress to connection opener: SNAT.\n");
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_dst;
			result.nat_port = v->orig_port;
		} else {
			CALI_DEBUG("CT-TCP Hit! NAT REV entry but not connection opener: ESTABLISHED.\n");
			result.rc =	CALI_CT_ESTABLISHED;
		}

		break;
	case CALI_CT_TYPE_NORMAL:
		CALI_DEBUG("CT-TCP Hit! NORMAL entry.\n");
		CALI_VERB("CT-TCP   Created: %llu.\n", v->created);
		CALI_VERB("CT-TCP   Last seen: %llu.\n", v->last_seen);
		CALI_VERB("CT-TCP   A-to-B: seqno %u.\n", v->a_to_b.seqno);
		CALI_VERB("CT-TCP   A-to-B: syn_seen %d.\n", v->a_to_b.syn_seen);
		CALI_VERB("CT-TCP   A-to-B: ack_seen %d.\n", v->a_to_b.ack_seen);
		CALI_VERB("CT-TCP   A-to-B: fin_seen %d.\n", v->a_to_b.fin_seen);
		CALI_VERB("CT-TCP   A-to-B: rst_seen %d.\n", v->a_to_b.rst_seen);
		CALI_VERB("CT-TCP   A: whitelisted %d.\n", v->a_to_b.whitelisted);
		CALI_VERB("CT-TCP   B-to-A: seqno %u.\n", v->b_to_a.seqno);
		CALI_VERB("CT-TCP   B-to-A: syn_seen %d.\n", v->b_to_a.syn_seen);
		CALI_VERB("CT-TCP   B-to-A: ack_seen %d.\n", v->b_to_a.ack_seen);
		CALI_VERB("CT-TCP   B-to-A: fin_seen %d.\n", v->b_to_a.fin_seen);
		CALI_VERB("CT-TCP   B-to-A: rst_seen %d.\n", v->b_to_a.rst_seen);
		CALI_VERB("CT-TCP   B: whitelisted %d.\n", v->b_to_a.whitelisted);

		result.rc =	CALI_CT_ESTABLISHED;

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		break;
	default:
		CALI_DEBUG("CT-TCP Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	if (CALI_TC_FLAGS_TO_HOST(flags)) {
		// Source of the packet is the endpoint, so check the src whitelist.
		if (src_to_dst->whitelisted) {
			// Packet was whitelisted by the policy attached to this endpoint.
			CALI_VERB("CT-TCP Packet whitelisted by this workload's policy.\n");
		} else {
			// Only whitelisted by the other side?
			CALI_DEBUG("CT-TCP Packet not allowed by ingress/egress whitelist flags (TH).\n");
			result.rc = CALI_CT_INVALID;
		}
	} else {
		// Dest of the packet is the workload, so check the dest whitelist.
		if (dst_to_src->whitelisted) {
			// Packet was whitelisted by the policy attached to this endpoint.
			CALI_VERB("CT-TCP Packet whitelisted by this workload's policy.\n");
		} else {
			// Only whitelisted by the other side?
			CALI_DEBUG("CT-TCP Packet not allowed by ingress/egress whitelist flags (FH).\n");
			result.rc = CALI_CT_INVALID;
		}
	}

	if (tcp_header->rst) {
		CALI_DEBUG("CT-TCP RST seen, marking CT entry.\n");
		// TODO: We should only take account of RST packets that are in
		// the right window.
		// TODO if we trust the RST, could just drop the CT entries.
		src_to_dst->rst_seen = 1;
	}
	if (tcp_header->fin) {
		CALI_VERB("CT-TCP FIN seen, marking CT entry.\n");
		src_to_dst->fin_seen = 1;
	}

	if (tcp_header->syn && tcp_header->ack) {
		if (dst_to_src->syn_seen && (dst_to_src->seqno + 1) == tcp_header->ack_seq) {
			CALI_VERB("CT-TCP SYN+ACK seen, marking CT entry.\n");
			src_to_dst->syn_seen = 1;
			src_to_dst->ack_seen = 1;
			src_to_dst->seqno = tcp_header->seq;
		} else {
			CALI_VERB("CT-TCP SYN+ACK seen but packet's ACK (%u) "
					"doesn't match other side's SYN (%u).\n",
					tcp_header->ack_seq, dst_to_src->seqno);
			// Have to let this through so source can reset?
		}
	} else if (tcp_header->ack && !src_to_dst->ack_seen && src_to_dst->syn_seen) {
		if (dst_to_src->syn_seen && (dst_to_src->seqno + 1) == tcp_header->ack_seq) {
			CALI_VERB("CT-TCP ACK seen, marking CT entry.\n");
			src_to_dst->ack_seen = 1;
		} else {
			CALI_VERB("CT-TCP ACK seen but packet's ACK (%u) doesn't "
					"match other side's SYN (%u).\n",
					tcp_header->ack_seq, dst_to_src->seqno);
			// Have to let this through so source can reset?
		}
	} else {
		// Normal packet, check that the handshake is complete.
		if (!dst_to_src->ack_seen) {
			CALI_VERB("CT-TCP Non-flagged packet but other side has never ACKed.\n");
			// Have to let this through so source can reset?
		} else {
			CALI_VERB("CT-TCP Non-flagged packet and other side has ACKed.\n");
		}
	}

	CALI_DEBUG("CT-TCP result: %d.\n", result.rc);
	return result;

	out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_DEBUG("CT-TCP result: NEW.\n");
	return result;
}


static CALI_BPF_INLINE struct calico_ct_result calico_ct_v4_udp_lookup(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		 enum calico_tc_flags flags) {

	CALI_VERB("CT-UDP lookup from %x:%d\n", be32_to_host(ip_src), sport);
	CALI_VERB("CT-UDP lookup to   %x:%d\n", be32_to_host(ip_dst), dport);

	struct calico_ct_result result = {};

	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	struct calico_ct_key k;
	if (srcLTDest) {
		k = (struct calico_ct_key) {
			.protocol = IPPROTO_UDP,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
	} else  {
		k = (struct calico_ct_key) {
			.protocol = IPPROTO_UDP,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
	}
	dump_ct_key(&k, flags);

	struct calico_ct_value *v = bpf_map_lookup_elem(&calico_ct_map_v4, &k);
	if (!v) {
		CALI_DEBUG("CT-UDP Miss.\n");
		goto out_lookup_fail;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	struct calico_ct_leg *src_to_dst, *dst_to_src;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALI_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALI_VERB("CT-UDP Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			CALI_VERB("CT-UDP Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			src_to_dst = &tracking_v->a_to_b;
			dst_to_src = &tracking_v->b_to_a;
			result.nat_ip = v->nat_rev_key.addr_b;
			result.nat_port = v->nat_rev_key.port_b;
		} else {
			src_to_dst = &tracking_v->b_to_a;
			dst_to_src = &tracking_v->a_to_b;
			result.nat_ip = v->nat_rev_key.addr_a;
			result.nat_port = v->nat_rev_key.port_a;
		}

		if (CALI_TC_FLAGS_TO_HOST(flags)) {
			// Since we found a forward NAT entry, we know that it's the destination
			// that needs to be NATted.
			result.rc =	CALI_CT_ESTABLISHED_DNAT;
		} else {
			result.rc =	CALI_CT_ESTABLISHED;
		}
		break;
	case CALI_CT_TYPE_NAT_REV:
		// A reverse NAT entry; this means that the conntrack entry was keyed on the post-NAT
		// IPs.  We'll only ever see a NAT entry if the NAT happened on this host.  However,
		// if the source and destination of the traffic are on the same host then we'll end up here
		// in both the source workload's ingress hook and the destination workload's ingress hook.

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		if (!CALI_TC_FLAGS_TO_HOST(flags) && dst_to_src->opener) {
			// Packet is heading away from the host namespace; either entering a workload or
			// leaving via a host endpoint, actually reverse the NAT.
			CALI_DEBUG("CT-UDP Hit! NAT REV entry at ingress to connection opener: SNAT.\n");
			result.rc =	CALI_CT_ESTABLISHED_SNAT;
			result.nat_ip = v->orig_dst;
			result.nat_port = v->orig_port;
		} else {
			CALI_DEBUG("CT-UDP Hit! NAT REV entry but not connection opener: ESTABLISHED.\n");
			result.rc =	CALI_CT_ESTABLISHED;
		}

		break;
	case CALI_CT_TYPE_NORMAL:
		CALI_VERB("CT-UDP Hit! NORMAL entry.\n");
		CALI_VERB("CT-UDP   Created: %llu.\n", v->created);
		CALI_VERB("CT-UDP   Last seen: %llu.\n", v->last_seen);
		CALI_VERB("CT-UDP   A: whitelisted %d.\n", v->a_to_b.whitelisted);
		CALI_VERB("CT-UDP   B: whitelisted %d.\n", v->b_to_a.whitelisted);

		result.rc =	CALI_CT_ESTABLISHED;

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		break;
	default:
		CALI_VERB("CT-UDP Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	if (CALI_TC_FLAGS_TO_HOST(flags)) {
		// Source of the packet is the endpoint, so check the src whitelist.
		if (src_to_dst->whitelisted) {
			// Packet was whitelisted by the policy attached to this endpoint.
			CALI_VERB("CT-TCP Packet whitelisted by this workload's policy.\n");
		} else {
			// Only whitelisted by the other side?
			CALI_DEBUG("CT-TCP Packet not allowed by ingress/egress whitelist flags (TH).\n");
			result.rc = CALI_CT_INVALID;
		}
	} else {
		// Dest of the packet is the workload, so check the dest whitelist.
		if (dst_to_src->whitelisted) {
			// Packet was whitelisted by the policy attached to this endpoint.
			CALI_VERB("CT-TCP Packet whitelisted by this workload's policy.\n");
		} else {
			// Only whitelisted by the other side?
			CALI_DEBUG("CT-TCP Packet not allowed by ingress/egress whitelist flags (FH).\n");
			result.rc = CALI_CT_INVALID;
		}
	}

	CALI_VERB("CT-UDP result: %d.\n", result.rc);
	return result;

	out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_VERB("CT-UDP result: NEW.\n");
	return result;
}


static CALI_BPF_INLINE struct calico_ct_result calico_ct_v4_icmp_lookup(
		__be32 ip_src, __be32 ip_dst, struct icmphdr *icmp_header,
		 enum calico_tc_flags flags) {

	CALI_VERB("CT-ICMP lookup from %x\n", be32_to_host(ip_src));
	CALI_VERB("CT-ICMP lookup to   %x\n", be32_to_host(ip_dst));

	struct calico_ct_result result = {};
	__u16 sport=0, dport=0;
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	struct calico_ct_key k;
	if (srcLTDest) {
		k = (struct calico_ct_key) {
			.protocol = IPPROTO_ICMP,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
	} else  {
		k = (struct calico_ct_key) {
			.protocol = IPPROTO_ICMP,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
	}
	dump_ct_key(&k, flags);

	struct calico_ct_value *v = bpf_map_lookup_elem(&calico_ct_map_v4, &k);
	if (!v) {
		CALI_DEBUG("CT-ICMP Miss.\n");
		goto out_lookup_fail;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	struct calico_ct_leg *src_to_dst, *dst_to_src;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALI_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALI_DEBUG("CT-ICMP Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			CALI_DEBUG("CT-ICMP Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			src_to_dst = &tracking_v->a_to_b;
			dst_to_src = &tracking_v->b_to_a;
		} else {
			src_to_dst = &tracking_v->b_to_a;
			dst_to_src = &tracking_v->a_to_b;
		}

		// Since we found a forward NAT entry, we know that it's the destination
		// that needs to be NATted.
		result.rc =	CALI_CT_ESTABLISHED_DNAT;
		result.nat_ip = tracking_v->orig_dst;
		break;
	case CALI_CT_TYPE_NAT_REV:
		// Since we found a reverse NAT entry, we know that this is response
		// traffic so we'll need to SNAT it.
		CALI_DEBUG("CT-ICMP Hit! NAT REV entry.\n");
		result.rc =	CALI_CT_ESTABLISHED_SNAT;
		result.nat_ip = v->orig_dst;

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		break;
	case CALI_CT_TYPE_NORMAL:
		CALI_DEBUG("CT-ICMP Hit! NORMAL entry.\n");
		CALI_VERB("CT-ICMP   Created: %llu.\n", v->created);
		CALI_VERB("CT-ICMP   Last seen: %llu.\n", v->last_seen);
		CALI_VERB("CT-ICMP   A: whitelisted %d.\n", v->a_to_b.whitelisted);
		CALI_VERB("CT-ICMP   B: whitelisted %d.\n", v->b_to_a.whitelisted);

		result.rc =	CALI_CT_ESTABLISHED;

		if (srcLTDest) {
			src_to_dst = &v->a_to_b;
			dst_to_src = &v->b_to_a;
		} else {
			src_to_dst = &v->b_to_a;
			dst_to_src = &v->a_to_b;
		}

		break;
	default:
		CALI_DEBUG("CT-ICMP Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	if (CALI_TC_FLAGS_TO_HOST(flags)) {
		// Source of the packet is the workload, so check the src whitelist.
		if (src_to_dst->whitelisted) {
			// Packet was whitelisted by the policy attached to this workload.
			CALI_VERB("CT-ICMP Packet whitelisted by this workload's policy.\n");
		} else {
			// Only whitelisted by the other side?
			CALI_VERB("CT-ICMP Packet not allowed by ingress/egress whitelist flags.\n");
			result.rc = CALI_CT_INVALID;
		}
	} else {
		// Dest of the packet is the workload, so check the dest whitelist.
		if (dst_to_src->whitelisted) {
			// Packet was whitelisted by the policy attached to this workload.
			CALI_VERB("CT-ICMP Packet whitelisted by this workload's policy.\n");
		} else {
			// Only whitelisted by the other side?
			CALI_VERB("CT-ICMP Packet not allowed by ingress/egress whitelist flags.\n");
			result.rc = CALI_CT_INVALID;
		}
	}

	CALI_DEBUG("CT-ICMP result: %d.\n", result.rc);
	return result;

	out_lookup_fail:
	result.rc = CALI_CT_NEW;
	CALI_DEBUG("CT-ICMP result: NEW.\n");
	return result;
}


#endif /* __CALI_CONNTRACK_H__ */
