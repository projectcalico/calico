#ifndef __CALICO_CONNTRACK_H__
#define __CALICO_CONNTRACK_H__

#include <linux/in.h>
#import "bpf.h"

// Connection tracking.

struct calico_ct_key {
	uint32_t protocol;
	__be32 addr_a, addr_b; // NBO
	uint16_t port_a, port_b; // HBO
};

enum CALICO_CT_TYPE {
	CALICO_CT_TYPE_NORMAL = 0,  // Non-NATted entry.
	CALICO_CT_TYPE_NAT_FWD = 1, // Forward entry for a DNATted flow, keyed on orig src/dst. Points to the reverse entry.
	CALICO_CT_TYPE_NAT_REV = 2, // "Reverse" entry for a NATted flow, contains NAT + tracking information.
};

struct calico_ct_leg {
	__u32 seqno;

	__u32 syn_seen:1;
	__u32 ack_seen:1;
	__u32 fin_seen:1;
	__u32 rst_seen:1;

	__u32 egress_whitelisted:1;
	__u32 ingress_whitelisted:1;
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
		// CALICO_CT_TYPE_NORMAL and CALICO_CT_TYPE_NAT_REV.
		struct {
			struct calico_ct_leg a_to_b; // 8
			struct calico_ct_leg b_to_a; // 16

			// CALICO_CT_TYPE_NAT_REV only.
			__u32 orig_dst;                    // 20
			__u16 orig_port;                   // 22
			__u8 pad1[2];                      // 24
		};

		// CALICO_CT_TYPE_NAT_FWD; key for the CALICO_CT_TYPE_NAT_REV entry.
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

static CALICO_BPF_INLINE void dump_ct_key(struct calico_ct_key *k, enum calico_tc_flags flags) {
	CALICO_DEBUG_AT("CT-TCP   key A=%x:%d proto=%d\n", be32_to_host(k->addr_a), k->port_a, (int)k->protocol);
	CALICO_DEBUG_AT("CT-TCP   key B=%x:%d size=%d\n", be32_to_host(k->addr_b), k->port_b, (int)sizeof(struct calico_ct_key));
}

static CALICO_BPF_INLINE int calico_ct_v4_create_tracking(
		struct __sk_buff *skb,
		__u8 ip_proto,
		struct calico_ct_key *k, enum CALICO_CT_TYPE type,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		__be32 orig_dst, __u16 orig_dport,
		__be32 seq, bool syn, enum calico_tc_flags flags) {

	if ((skb->mark & CALICO_SKB_MARK_FROM_WORKLOAD_MASK) == CALICO_SKB_MARK_FROM_WORKLOAD) {
		// Packet already marked as being from another workload, which will
		// have created a conntrack entry.  Look that one up instead of
		// creating one.
		CALICO_DEBUG_AT("CT-TCP Asked to create entry but packet is marked as "
				"from another workload, doing lookup\n");
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
			CALICO_DEBUG_AT("CT-TCP Packet marked as from workload but got a conntrack miss!\n");
			goto create;
		}
		CALICO_DEBUG_AT("CT-TCP Found expected create entry, updating...\n");
		if (srcLTDest) {
			ct_value->a_to_b.seqno = seq;
			ct_value->a_to_b.syn_seen = syn;
			if (flags & CALICO_TC_INGRESS) {
				ct_value->b_to_a.ingress_whitelisted = 1;
			} else {
				ct_value->a_to_b.egress_whitelisted = 1;
			}
		} else  {
			ct_value->b_to_a.seqno = seq;
			ct_value->b_to_a.syn_seen = syn;
			if (flags & CALICO_TC_INGRESS) {
				ct_value->a_to_b.ingress_whitelisted = 1;
			} else {
				ct_value->b_to_a.egress_whitelisted = 1;
			}
		}

		return 0;
	}

	__u64 now;
	create:
	now = bpf_ktime_get_ns();
	CALICO_DEBUG_AT("CT-TCP Creating entry at %llu.\n", now);
	struct calico_ct_value ct_value = {};
	ct_value.created=now;
	ct_value.last_seen=now;
	ct_value.type = type;
	ct_value.orig_dst = orig_dst;
	ct_value.orig_port = orig_dport;
	struct calico_ct_leg *our_dir, *oth_dir;
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	if (srcLTDest) {
		*k = (struct calico_ct_key) {
			.protocol = ip_proto,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		our_dir = &ct_value.a_to_b;
		oth_dir = &ct_value.b_to_a;
	} else  {
		*k = (struct calico_ct_key) {
			.protocol = ip_proto,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		our_dir = &ct_value.b_to_a;
		oth_dir = &ct_value.a_to_b;
	}

	dump_ct_key(k, flags);

	our_dir->seqno = seq;
	our_dir->syn_seen = syn;
	if (flags & CALICO_TC_INGRESS) {
		oth_dir->ingress_whitelisted = true;
	} else {
		our_dir->egress_whitelisted = true;
	}
	int err = bpf_map_update_elem(&calico_ct_map_v4, k, &ct_value, 0);
	CALICO_DEBUG_AT("CT-TCP Create result: %d.\n", err);
	return err;
}

static CALICO_BPF_INLINE int calico_ct_v4_create_nat_fwd(
		__u8 ip_proto,
		struct calico_ct_key *rk, __be32 ip_src,
		__be32 ip_dst, __u16 sport, __u16 dport, enum calico_tc_flags flags) {
	__u64 now = bpf_ktime_get_ns();
	CALICO_DEBUG_AT("CT-TCP Creating entry at %llu.\n", now);
	struct calico_ct_value ct_value = {
		.type = CALICO_CT_TYPE_NAT_FWD,
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
		CALICO_DEBUG_AT("CT-TCP Create result: %d.\n", err);
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
		CALICO_DEBUG_AT("CT-TCP Create result: %d.\n", err);
		return err;
	}
}

static CALICO_BPF_INLINE int calico_ct_v4_tcp_create(
		struct __sk_buff *skb,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		struct tcphdr *tcp_header, enum calico_tc_flags flags) {
	struct calico_ct_key k;
	return calico_ct_v4_create_tracking(skb,
			IPPROTO_TCP, &k, CALICO_CT_TYPE_NORMAL,
			ip_src, ip_dst, sport, dport, 0, 0,
			tcp_header->seq, tcp_header->syn, flags);
}

static CALICO_BPF_INLINE int calico_ct_v4_udp_create(
		struct __sk_buff *skb,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	return calico_ct_v4_create_tracking(skb,
			IPPROTO_UDP, &k, CALICO_CT_TYPE_NORMAL,
			ip_src, ip_dst, sport, dport, 0, 0, 0, 0, flags);
}

static CALICO_BPF_INLINE int calico_ct_v4_icmp_create(
		struct __sk_buff *skb,
		__be32 ip_src, __be32 ip_dst,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	return calico_ct_v4_create_tracking(skb,
			IPPROTO_ICMP, &k, CALICO_CT_TYPE_NORMAL,
			ip_src, ip_dst, 0, 0, 0, 0, 0, 0, flags);
}

static CALICO_BPF_INLINE int calico_ct_v4_tcp_create_nat(
		struct __sk_buff *skb,
		__be32 orig_src, __be32 orig_dst, __u16 orig_sport, __u16 orig_dport,
		__be32 nat_dst, __u16 nat_dport, struct tcphdr *tcp_header,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	calico_ct_v4_create_tracking(skb,
			IPPROTO_TCP, &k, CALICO_CT_TYPE_NAT_REV, orig_src,
			nat_dst, orig_sport, nat_dport, orig_dst, orig_dport,
			tcp_header->seq, tcp_header->syn, flags);
	calico_ct_v4_create_nat_fwd(IPPROTO_TCP, &k, orig_src, orig_dst, orig_sport,
			orig_dport, flags);
	return 0;
}

static CALICO_BPF_INLINE int calico_ct_v4_udp_create_nat(
		struct __sk_buff *skb,
		__be32 orig_src, __be32 orig_dst, __u16 orig_sport, __u16 orig_dport,
		__be32 nat_dst, __u16 nat_dport,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	calico_ct_v4_create_tracking(skb,
			IPPROTO_UDP, &k, CALICO_CT_TYPE_NAT_REV, orig_src,
			nat_dst, orig_sport, nat_dport, orig_dst, orig_dport,
			0, 0, flags);
	calico_ct_v4_create_nat_fwd(IPPROTO_UDP, &k, orig_src, orig_dst, orig_sport,
			orig_dport, flags);
	return 0;
}

static CALICO_BPF_INLINE int calico_ct_v4_icmp_create_nat(
		struct __sk_buff *skb,
		__be32 orig_src, __be32 orig_dst,
		__be32 nat_dst,
		enum calico_tc_flags flags) {
	struct calico_ct_key k;
	calico_ct_v4_create_tracking(skb,
			IPPROTO_ICMP, &k, CALICO_CT_TYPE_NAT_REV, orig_src,
			nat_dst, 0, 0, orig_dst, 0, 0, 0, flags);
	calico_ct_v4_create_nat_fwd(IPPROTO_ICMP, &k, orig_src, orig_dst, 0, 0, flags);
	return 0;
}

enum calico_ct_result_type {
	CALICO_CT_NEW,
	CALICO_CT_ESTABLISHED,
	CALICO_CT_ESTABLISHED_SNAT,
	CALICO_CT_ESTABLISHED_DNAT,
	CALICO_CT_INVALID,
};

struct calico_ct_result {
	enum calico_ct_result_type rc;

	// For CALICO_CT_ESTABLISHED_SNAT and CALICO_CT_ESTABLISHED_DNAT.
	__be32 nat_ip;
	__u32 nat_port;
};

static CALICO_BPF_INLINE void calico_ct_v4_tcp_delete(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		enum calico_tc_flags flags) {
	CALICO_DEBUG_AT("CT-TCP delete from %x:%d\n", be32_to_host(ip_src), sport);
	CALICO_DEBUG_AT("CT-TCP delete to   %x:%d\n", be32_to_host(ip_dst), dport);

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
	CALICO_DEBUG_AT("CT-TCP delete result: %d\n", rc);
}

static CALICO_BPF_INLINE struct calico_ct_result calico_ct_v4_tcp_lookup(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		struct tcphdr *tcp_header, enum calico_tc_flags flags) {

	CALICO_DEBUG_AT("CT-TCP lookup from %x:%d\n", be32_to_host(ip_src), sport);
	CALICO_DEBUG_AT("CT-TCP lookup to   %x:%d\n", be32_to_host(ip_dst), dport);
	CALICO_DEBUG_AT("CT-TCP   packet seq = %u\n", tcp_header->seq);
	CALICO_DEBUG_AT("CT-TCP   packet ack_seq = %u\n", tcp_header->ack_seq);
	CALICO_DEBUG_AT("CT-TCP   packet syn = %d\n", tcp_header->syn);
	CALICO_DEBUG_AT("CT-TCP   packet ack = %d\n", tcp_header->ack);
	CALICO_DEBUG_AT("CT-TCP   packet fin = %d\n", tcp_header->fin);
	CALICO_DEBUG_AT("CT-TCP   packet rst = %d\n", tcp_header->rst);

	struct calico_ct_result result = {};

	if (tcp_header->syn && !tcp_header->ack) {
		// SYN should always go through policy.
		CALICO_DEBUG_AT("CT-TCP Packet is a SYN, short-circuiting lookup.\n");
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
		CALICO_DEBUG_AT("CT-TCP Miss.\n");
		goto out_lookup_fail;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	struct calico_ct_leg *our_dir, *oth_dir;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALICO_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALICO_DEBUG_AT("CT-TCP Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			CALICO_DEBUG_AT("CT-TCP Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			our_dir = &tracking_v->a_to_b;
			oth_dir = &tracking_v->b_to_a;
		} else {
			our_dir = &tracking_v->b_to_a;
			oth_dir = &tracking_v->a_to_b;
		}

		// Since we found a forward NAT entry, we know that it's the destination
		// that needs to be NATted.
		result.rc =	CALICO_CT_ESTABLISHED_DNAT;
		result.nat_ip = tracking_v->orig_dst;
		result.nat_port = tracking_v->orig_port;
		break;
	case CALICO_CT_TYPE_NAT_REV:
		// Since we found a reverse NAT entry, we know that this is response
		// traffic so we'll need to SNAT it.
		CALICO_DEBUG_AT("CT-TCP Hit! NAT REV entry.\n");
		result.rc =	CALICO_CT_ESTABLISHED_SNAT;
		result.nat_ip = v->orig_dst;
		result.nat_port = v->orig_port;

		if (srcLTDest) {
			our_dir = &v->a_to_b;
			oth_dir = &v->b_to_a;
		} else {
			our_dir = &v->b_to_a;
			oth_dir = &v->a_to_b;
		}

		break;
	case CALICO_CT_TYPE_NORMAL:
		CALICO_DEBUG_AT("CT-TCP Hit! NORMAL entry.\n");
		CALICO_DEBUG_AT("CT-TCP   Created: %llu.\n", v->created);
		CALICO_DEBUG_AT("CT-TCP   Last seen: %llu.\n", v->last_seen);
		CALICO_DEBUG_AT("CT-TCP   A-to-B: seqno %u.\n", v->a_to_b.seqno);
		CALICO_DEBUG_AT("CT-TCP   A-to-B: syn_seen %d.\n", v->a_to_b.syn_seen);
		CALICO_DEBUG_AT("CT-TCP   A-to-B: ack_seen %d.\n", v->a_to_b.ack_seen);
		CALICO_DEBUG_AT("CT-TCP   A-to-B: fin_seen %d.\n", v->a_to_b.fin_seen);
		CALICO_DEBUG_AT("CT-TCP   A-to-B: rst_seen %d.\n", v->a_to_b.rst_seen);
		CALICO_DEBUG_AT("CT-TCP   A: egress_whitelisted %d.\n", v->a_to_b.egress_whitelisted);
		CALICO_DEBUG_AT("CT-TCP   A: ingress_whitelisted %d.\n", v->a_to_b.ingress_whitelisted);
		CALICO_DEBUG_AT("CT-TCP   B-to-A: seqno %u.\n", v->b_to_a.seqno);
		CALICO_DEBUG_AT("CT-TCP   B-to-A: syn_seen %d.\n", v->b_to_a.syn_seen);
		CALICO_DEBUG_AT("CT-TCP   B-to-A: ack_seen %d.\n", v->b_to_a.ack_seen);
		CALICO_DEBUG_AT("CT-TCP   B-to-A: fin_seen %d.\n", v->b_to_a.fin_seen);
		CALICO_DEBUG_AT("CT-TCP   B-to-A: rst_seen %d.\n", v->b_to_a.rst_seen);
		CALICO_DEBUG_AT("CT-TCP   B: egress_whitelisted %d.\n", v->b_to_a.egress_whitelisted);
		CALICO_DEBUG_AT("CT-TCP   B: ingress_whitelisted %d.\n", v->b_to_a.ingress_whitelisted);

		result.rc =	CALICO_CT_ESTABLISHED;

		if (srcLTDest) {
			our_dir = &v->a_to_b;
			oth_dir = &v->b_to_a;
		} else {
			our_dir = &v->b_to_a;
			oth_dir = &v->a_to_b;
		}

		break;
	default:
		CALICO_DEBUG_AT("CT-TCP Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	// TODO Update once host endpoints come along.
	// Packet towards a workload.
	if (our_dir->ingress_whitelisted || our_dir->egress_whitelisted) {
		// Packet was whitelisted by the policy attached to this workload.
		CALICO_DEBUG_AT("CT-TCP Packet whitelisted by this workload's policy.\n");
	} else if (oth_dir->ingress_whitelisted) {
		// Traffic between two workloads on the same host; the only way
		// the the ingress flag can get set on the other side of the
		// connection is if this workload opened the connection and it
		// was whitelisted at the other side.
		CALICO_DEBUG_AT("CT-TCP Packet whitelisted by other workload's policy.\n");
	} else {
		// oth_dir->egress_whitelisted?  In this case, the other workload
		// sent us a connection but we never upgraded it to
		// ingress_whitelisted; it must not have passed our local ingress
		// policy.
		CALICO_DEBUG_AT("CT-TCP Packet not allowed by ingress/egress whitelist flags.\n");
		result.rc = CALICO_CT_INVALID;
	}

	if (tcp_header->rst) {
		CALICO_DEBUG_AT("CT-TCP RST seen, marking CT entry.\n");
		// TODO: We should only take account of RST packets that are in
		// the right window.
		our_dir->rst_seen = 1;
	}
	if (tcp_header->fin) {
		CALICO_DEBUG_AT("CT-TCP FIN seen, marking CT entry.\n");
		our_dir->fin_seen = 1;
	}

	if (tcp_header->syn && tcp_header->ack) {
		if (oth_dir->syn_seen && (oth_dir->seqno + 1) == tcp_header->ack_seq) {
			CALICO_DEBUG_AT("CT-TCP SYN+ACK seen, marking CT entry.\n");
			our_dir->syn_seen = 1;
			our_dir->ack_seen = 1;
			our_dir->seqno = tcp_header->seq;
		} else {
			CALICO_DEBUG_AT("CT-TCP SYN+ACK seen but packet's ACK (%u) "
					"doesn't match other side's SYN (%u).\n",
					tcp_header->ack_seq, oth_dir->seqno);
			// Have to let this through so source can reset?
		}
	} else if (tcp_header->ack && !our_dir->ack_seen && our_dir->syn_seen) {
		if (oth_dir->syn_seen && (oth_dir->seqno + 1) == tcp_header->ack_seq) {
			CALICO_DEBUG_AT("CT-TCP ACK seen, marking CT entry.\n");
			our_dir->ack_seen = 1;
		} else {
			CALICO_DEBUG_AT("CT-TCP ACK seen but packet's ACK (%u) doesn't "
					"match other side's SYN (%u).\n",
					tcp_header->ack_seq, oth_dir->seqno);
			// Have to let this through so source can reset?
		}
	} else {
		// Normal packet, check that the handshake is complete.
		if (!oth_dir->ack_seen) {
			CALICO_DEBUG_AT("CT-TCP Non-flagged packet but other side has never ACKed.\n");
			// Have to let this through so source can reset?
		} else {
			CALICO_DEBUG_AT("CT-TCP Non-flagged packet and other side has ACKed.\n");
		}
	}

	CALICO_DEBUG_AT("CT-TCP result: %d.\n", result.rc);
	return result;

	out_lookup_fail:
	result.rc = CALICO_CT_NEW;
	CALICO_DEBUG_AT("CT-TCP result: NEW.\n");
	return result;
}


static CALICO_BPF_INLINE struct calico_ct_result calico_ct_v4_udp_lookup(
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport,
		 enum calico_tc_flags flags) {

	CALICO_DEBUG_AT("CT-UDP lookup from %x:%d\n", be32_to_host(ip_src), sport);
	CALICO_DEBUG_AT("CT-UDP lookup to   %x:%d\n", be32_to_host(ip_dst), dport);

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
		CALICO_DEBUG_AT("CT-UDP Miss.\n");
		goto out_lookup_fail;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	struct calico_ct_leg *our_dir, *oth_dir;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALICO_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALICO_DEBUG_AT("CT-UDP Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			CALICO_DEBUG_AT("CT-UDP Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			our_dir = &tracking_v->a_to_b;
			oth_dir = &tracking_v->b_to_a;
		} else {
			our_dir = &tracking_v->b_to_a;
			oth_dir = &tracking_v->a_to_b;
		}

		// Since we found a forward NAT entry, we know that it's the destination
		// that needs to be NATted.
		result.rc =	CALICO_CT_ESTABLISHED_DNAT;
		result.nat_ip = tracking_v->orig_dst;
		result.nat_port = tracking_v->orig_port;
		break;
	case CALICO_CT_TYPE_NAT_REV:
		// Since we found a reverse NAT entry, we know that this is response
		// traffic so we'll need to SNAT it.
		CALICO_DEBUG_AT("CT-UDP Hit! NAT REV entry.\n");
		result.rc =	CALICO_CT_ESTABLISHED_SNAT;
		result.nat_ip = v->orig_dst;
		result.nat_port = v->orig_port;

		if (srcLTDest) {
			our_dir = &v->a_to_b;
			oth_dir = &v->b_to_a;
		} else {
			our_dir = &v->b_to_a;
			oth_dir = &v->a_to_b;
		}

		break;
	case CALICO_CT_TYPE_NORMAL:
		CALICO_DEBUG_AT("CT-UDP Hit! NORMAL entry.\n");
		CALICO_DEBUG_AT("CT-UDP   Created: %llu.\n", v->created);
		CALICO_DEBUG_AT("CT-UDP   Last seen: %llu.\n", v->last_seen);
		CALICO_DEBUG_AT("CT-UDP   A: egress_whitelisted %d.\n", v->a_to_b.egress_whitelisted);
		CALICO_DEBUG_AT("CT-UDP   A: ingress_whitelisted %d.\n", v->a_to_b.ingress_whitelisted);
		CALICO_DEBUG_AT("CT-UDP   B: egress_whitelisted %d.\n", v->b_to_a.egress_whitelisted);
		CALICO_DEBUG_AT("CT-UDP   B: ingress_whitelisted %d.\n", v->b_to_a.ingress_whitelisted);

		result.rc =	CALICO_CT_ESTABLISHED;

		if (srcLTDest) {
			our_dir = &v->a_to_b;
			oth_dir = &v->b_to_a;
		} else {
			our_dir = &v->b_to_a;
			oth_dir = &v->a_to_b;
		}

		break;
	default:
		CALICO_DEBUG_AT("CT-UDP Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	// TODO Update once host endpoints come along.
	// Packet towards a workload.
	if (our_dir->ingress_whitelisted || our_dir->egress_whitelisted) {
		// Packet was whitelisted by the policy attached to this workload.
		CALICO_DEBUG_AT("CT-UDP Packet whitelisted by this workload's policy.\n");
	} else if (oth_dir->ingress_whitelisted) {
		// Traffic between two workloads on the same host; the only way
		// the the ingress flag can get set on the other side of the
		// connection is if this workload opened the connection and it
		// was whitelisted at the other side.
		CALICO_DEBUG_AT("CT-UDP Packet whitelisted by other workload's policy.\n");
	} else {
		// oth_dir->egress_whitelisted?  In this case, the other workload
		// sent us a connection but we never upgraded it to
		// ingress_whitelisted; it must not have passed our local ingress
		// policy.
		CALICO_DEBUG_AT("CT-UDP Packet not allowed by ingress/egress whitelist flags.\n");
		result.rc = CALICO_CT_INVALID;
	}

	CALICO_DEBUG_AT("CT-UDP result: %d.\n", result.rc);
	return result;

	out_lookup_fail:
	result.rc = CALICO_CT_NEW;
	CALICO_DEBUG_AT("CT-UDP result: NEW.\n");
	return result;
}


static CALICO_BPF_INLINE struct calico_ct_result calico_ct_v4_icmp_lookup(
		__be32 ip_src, __be32 ip_dst, struct icmphdr *icmp_header,
		 enum calico_tc_flags flags) {

	CALICO_DEBUG_AT("CT-ICMP lookup from %x\n", be32_to_host(ip_src));
	CALICO_DEBUG_AT("CT-ICMP lookup to   %x\n", be32_to_host(ip_dst));

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
		CALICO_DEBUG_AT("CT-ICMP Miss.\n");
		goto out_lookup_fail;
	}

	__u64 now = bpf_ktime_get_ns();
	v->last_seen = now;

	struct calico_ct_leg *our_dir, *oth_dir;

	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALICO_CT_TYPE_NAT_FWD:
		// This is a forward NAT entry; since we do the bookkeeping on the
		// reverse entry, we need to do a second lookup.
		CALICO_DEBUG_AT("CT-ICMP Hit! NAT FWD entry, doing secondary lookup.\n");
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			CALICO_DEBUG_AT("CT-ICMP Miss when looking for secondary entry.\n");
			goto out_lookup_fail;
		}
		// Record timestamp.
		tracking_v->last_seen = now;

		if (ip_src == v->nat_rev_key.addr_a && sport == v->nat_rev_key.port_a) {
			our_dir = &tracking_v->a_to_b;
			oth_dir = &tracking_v->b_to_a;
		} else {
			our_dir = &tracking_v->b_to_a;
			oth_dir = &tracking_v->a_to_b;
		}

		// Since we found a forward NAT entry, we know that it's the destination
		// that needs to be NATted.
		result.rc =	CALICO_CT_ESTABLISHED_DNAT;
		result.nat_ip = tracking_v->orig_dst;
		break;
	case CALICO_CT_TYPE_NAT_REV:
		// Since we found a reverse NAT entry, we know that this is response
		// traffic so we'll need to SNAT it.
		CALICO_DEBUG_AT("CT-ICMP Hit! NAT REV entry.\n");
		result.rc =	CALICO_CT_ESTABLISHED_SNAT;
		result.nat_ip = v->orig_dst;

		if (srcLTDest) {
			our_dir = &v->a_to_b;
			oth_dir = &v->b_to_a;
		} else {
			our_dir = &v->b_to_a;
			oth_dir = &v->a_to_b;
		}

		break;
	case CALICO_CT_TYPE_NORMAL:
		CALICO_DEBUG_AT("CT-ICMP Hit! NORMAL entry.\n");
		CALICO_DEBUG_AT("CT-ICMP   Created: %llu.\n", v->created);
		CALICO_DEBUG_AT("CT-ICMP   Last seen: %llu.\n", v->last_seen);
		CALICO_DEBUG_AT("CT-ICMP   A: egress_whitelisted %d.\n", v->a_to_b.egress_whitelisted);
		CALICO_DEBUG_AT("CT-ICMP   A: ingress_whitelisted %d.\n", v->a_to_b.ingress_whitelisted);
		CALICO_DEBUG_AT("CT-ICMP   B: egress_whitelisted %d.\n", v->b_to_a.egress_whitelisted);
		CALICO_DEBUG_AT("CT-ICMP   B: ingress_whitelisted %d.\n", v->b_to_a.ingress_whitelisted);

		result.rc =	CALICO_CT_ESTABLISHED;

		if (srcLTDest) {
			our_dir = &v->a_to_b;
			oth_dir = &v->b_to_a;
		} else {
			our_dir = &v->b_to_a;
			oth_dir = &v->a_to_b;
		}

		break;
	default:
		CALICO_DEBUG_AT("CT-ICMP Hit! UNKNOWN entry type.\n");
		goto out_lookup_fail;
	}

	// TODO Update once host endpoints come along.
	// Packet towards a workload.
	if (our_dir->ingress_whitelisted || our_dir->egress_whitelisted) {
		// Packet was whitelisted by the policy attached to this workload.
		CALICO_DEBUG_AT("CT-ICMP Packet whitelisted by this workload's policy.\n");
	} else if (oth_dir->ingress_whitelisted) {
		// Traffic between two workloads on the same host; the only way
		// the the ingress flag can get set on the other side of the
		// connection is if this workload opened the connection and it
		// was whitelisted at the other side.
		CALICO_DEBUG_AT("CT-ICMP Packet whitelisted by other workload's policy.\n");
	} else {
		// oth_dir->egress_whitelisted?  In this case, the other workload
		// sent us a connection but we never upgraded it to
		// ingress_whitelisted; it must not have passed our local ingress
		// policy.
		CALICO_DEBUG_AT("CT-ICMP Packet not allowed by ingress/egress whitelist flags.\n");
		result.rc = CALICO_CT_INVALID;
	}

	CALICO_DEBUG_AT("CT-ICMP result: %d.\n", result.rc);
	return result;

	out_lookup_fail:
	result.rc = CALICO_CT_NEW;
	CALICO_DEBUG_AT("CT-ICMP result: NEW.\n");
	return result;
}


#endif /* __CALICO_CONNTRACK_H__ */
