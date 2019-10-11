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

struct calico_ct_tcp_state {
	__u32 seqno;

	__u32 syn_seen :1;
	__u32 ack_seen :1;
	__u32 fin_seen :1;
};

struct calico_ct_value {
	__u32 type;
	union {
		// CALICO_CT_TYPE_NORMAL and CALICO_CT_TYPE_NAT_REV.
		struct {
			struct calico_ct_tcp_state a_to_b, b_to_a;

			// CALICO_CT_TYPE_NAT_REV only.
			__u32 orig_dst;
			__u16 orig_port;
		};

		// CALICO_CT_TYPE_NAT_FWD; key for the CALICO_CT_TYPE_NAT_REV entry.
		struct calico_ct_key nat_rev_key;
	};
} __attribute__((packed));

struct bpf_map_def_extended __attribute__((section("maps"))) calico_ct_map_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_ct_key),
	.value_size = sizeof(struct calico_ct_value),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 512000, // arbitrary
	.pinning_strategy = 2 /* global namespace */,
};

static CALICO_BPF_INLINE int calico_ct_v4_tcp_create_tracking(struct calico_ct_key *k, enum CALICO_CT_TYPE type,
		__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport, __be32 orig_dst, __u16 orig_dport, struct tcphdr *tcp_header) {
	struct calico_ct_value ct_value = {};
	ct_value.type = type;
	ct_value.orig_dst = orig_dst;
	ct_value.orig_port = orig_dport;
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	if (srcLTDest) {
		*k = (struct calico_ct_key) {
			.protocol = IPPROTO_TCP,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		ct_value.a_to_b.seqno = tcp_header->seq;
		ct_value.a_to_b.syn_seen = 1;
		return bpf_map_update_elem(&calico_ct_map_v4, k, &ct_value, 0);
	} else  {
		*k = (struct calico_ct_key) {
			.protocol = IPPROTO_TCP,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		ct_value.b_to_a.seqno = tcp_header->seq;
		ct_value.b_to_a.syn_seen = 1;
		return bpf_map_update_elem(&calico_ct_map_v4, k, &ct_value, 0);
	}
}

static CALICO_BPF_INLINE int calico_ct_v4_tcp_create_nat_fwd(struct calico_ct_key *rk, __be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport) {
	struct calico_ct_value ct_value = {.type = CALICO_CT_TYPE_NAT_FWD};
	bool srcLTDest = (ip_src < ip_dst) || ((ip_src == ip_dst) && sport < dport);
	if (srcLTDest) {
		struct calico_ct_key k = {
			.protocol = IPPROTO_TCP,
			.addr_a = ip_src, .port_a = sport,
			.addr_b = ip_dst, .port_b = dport,
		};
		ct_value.nat_rev_key = *rk;
		return bpf_map_update_elem(&calico_ct_map_v4, &k, &ct_value, 0);
	} else  {
		struct calico_ct_key k = {
			.protocol = IPPROTO_TCP,
			.addr_a = ip_dst, .port_a = dport,
			.addr_b = ip_src, .port_b = sport,
		};
		ct_value.nat_rev_key = *rk;
		return bpf_map_update_elem(&calico_ct_map_v4, &k, &ct_value, 0);
	}
}

static CALICO_BPF_INLINE int calico_ct_v4_tcp_create(__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport, struct tcphdr *tcp_header) {
	struct calico_ct_key k;
	return calico_ct_v4_tcp_create_tracking(&k, CALICO_CT_TYPE_NORMAL, ip_src, ip_dst, sport, dport, 0, 0, tcp_header);
}

static CALICO_BPF_INLINE int calico_ct_v4_tcp_create_nat(__be32 orig_src, __be32 orig_dst, __u16 orig_sport, __u16 orig_dport,
				__be32 nat_dst, __u16 nat_dport, struct tcphdr *tcp_header) {
	struct calico_ct_key k;
	calico_ct_v4_tcp_create_tracking(&k, CALICO_CT_TYPE_NAT_REV, orig_src, nat_dst, orig_sport, nat_dport, orig_dst, orig_dport, tcp_header);
	calico_ct_v4_tcp_create_nat_fwd(&k, orig_src, orig_dst, orig_sport, orig_dport);
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

static CALICO_BPF_INLINE struct calico_ct_result calico_ct_v4_tcp_lookup(__be32 ip_src, __be32 ip_dst, __u16 sport, __u16 dport, struct tcphdr *tcp_header) {
	struct calico_ct_result result = {};

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

	struct calico_ct_value *v = bpf_map_lookup_elem(&calico_ct_map_v4, &k);
	if (!v) {
		goto out_lookup_fail;
	}

	// TODO connection state tracking!
	struct calico_ct_value *tracking_v;
	switch (v->type) {
	case CALICO_CT_TYPE_NAT_FWD:
		tracking_v = bpf_map_lookup_elem(&calico_ct_map_v4, &v->nat_rev_key);
		if (!tracking_v) {
			goto out_lookup_fail;
		}
		// Since we found a forward NAT entry, we know that it's the destination that needs to be NATted.
		result.rc =	CALICO_CT_ESTABLISHED_DNAT;
		result.nat_ip = tracking_v->orig_dst;
		result.nat_port = tracking_v->orig_port;
		goto out;
	case CALICO_CT_TYPE_NAT_REV:
		// Since we found a reverse NAT entry, we know that it's the source that needs to be NATted.
		result.rc =	CALICO_CT_ESTABLISHED_SNAT;
		result.nat_ip = v->orig_dst;
		result.nat_port = v->orig_port;
		goto out;
	case CALICO_CT_TYPE_NORMAL:
		result.rc =	CALICO_CT_ESTABLISHED;
		goto out;
	}

	out_lookup_fail:
	result.rc = CALICO_CT_NEW;

	out:
	return result;
}

#endif /* __CALICO_CONNTRACK_H__ */
