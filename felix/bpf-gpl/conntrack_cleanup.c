// Project Calico BPF dataplane programs.
// Copyright (c) 2024 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

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
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>

#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "counters.h"
#include "conntrack.h"
#include "conntrack_types.h"

const volatile struct cali_ct_cleanup_globals __globals;

struct ct_iter_ctx {
	__u64 now;
	__u32 num_seen;
	__u32 num_expired;
};

#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_ctc, cali_ctc, 1,
#else
CALI_MAP_NAMED(cali_v4_ctc, cali_ctc, 1,
#endif
		BPF_MAP_TYPE_HASH,
		struct calico_ct_key,
		struct calico_ct_key,
		512000,
		BPF_F_NO_PREALLOC
);

static __u64 sub_age(__u64 now, __u64 then) {
	__u64 age = now - then;
	if (age > (1ull<<63)) {
		// Wrapped, assume that means then > now.
		return 0;
	}
	return age;
}

static bool entry_expired(const struct calico_ct_key *key, const struct calico_ct_value *value, struct ct_iter_ctx *ctx) {
	__u64 max_age;

	switch (key->protocol) {
	case IPPROTO_TCP:
		if (value->a_to_b.rst_seen || value->b_to_a.rst_seen) {
			max_age = __globals.tcp_reset_seen;
		} else if (((value->flags & CALI_CT_FLAG_DSR_FWD) &&
					(value->a_to_b.fin_seen || value->b_to_a.fin_seen)) ||
				   (value->a_to_b.fin_seen && value->b_to_a.fin_seen)) {
			max_age = __globals.tcp_fins_seen;
		} else if (value->a_to_b.syn_seen && value->a_to_b.ack_seen &&
				   value->b_to_a.syn_seen && value->b_to_a.ack_seen ) {
			max_age = __globals.tcp_established;
		} else {
			max_age = __globals.tcp_pre_established;
		}
		break;
	case IPPROTO_UDP:
		max_age = __globals.udp_last_seen;
		break;
	case IPPROTO_ICMP_46:
		max_age = __globals.icmp_last_seen;
		break;
	default:
		max_age = __globals.generic_last_seen;
		break;
	}

	__u64 age = sub_age(ctx->now, value->last_seen);
	return age > max_age;
}

static long process_ct_entry(void *map, const void *key, void *value, void *ctx) {
	const struct calico_ct_key *ct_key = key;
	struct calico_ct_value *ct_value = value;
	struct calico_ct_value *rev_value;
	struct ct_iter_ctx *ictx = ctx;

	ictx->num_seen++;

	switch (ct_value->type) {
	case CALI_CT_TYPE_NORMAL:
		// Non-NAT entry, we only need to look at this entry to determine if it
		// has expired.
		if (entry_expired(ct_key, ct_value, ictx)) {
			cali_ct_delete_elem(ct_key);
		}
		break;
	case CALI_CT_TYPE_NAT_FWD:
		// One half of a NAT entry.  The "forward" NAT entry is just a pointer
		// to the "reverse" one, where we do the book-keeping.  In particular,
		// the last-seen timestamp on the "reverse" entry is updated when we see
		// traffic in either direction.
		rev_value = cali_ct_lookup_elem(&ct_value->nat_rev_key);
		if (!rev_value) {
			// No reverse value found, see if this is a new entry.
			__u64 age = sub_age(ictx->now, ct_value->last_seen);
			if (age < __globals.creation_grace) {
				// New entry, assume we're racing with creation.
				break;
			}

			// Entry is not fresh so it looks invalid.  Clean it up.
			cali_ct_delete_elem(ct_key);
			break;
		}

		// Got a reverse value, check if it has expired.
		if (entry_expired(&ct_value->nat_rev_key, rev_value, ictx)) {
			// Expired, mark the entries for cleanup.  We can't just delete
			// them now because it's not safe to delete _other_ entries from
			// the map while iterating.
			cali_ctc_update_elem(&ct_value->nat_rev_key, ct_key, BPF_ANY);
		}

		break;
	case CALI_CT_TYPE_NAT_REV:
		// One half of a NAT entry.  The "reverse" entry is updated when we see
		// traffic in either direction.
		if (entry_expired(ct_key, ct_value, ictx)) {
			// Reverse entry has expired, but we don't know the forward entry
			// that matches it.  See if it's in the map already.
			struct calico_ct_key *fwd_key = cali_ctc_lookup_elem(ct_key);
			if (!fwd_key) {
				// Not in the map, store a dummy key.
				struct calico_ct_key dummy_key = {};
				cali_ctc_update_elem(ct_key, &dummy_key, BPF_ANY);
			}
		}
		break;
	}

	return 0;
}

static long process_ctc_entry(void *map, const void *key, void *value, void *ctx) {
	// Map stores mapping from reverse key to forward key (if known).
	const struct calico_ct_key *rev_key = key;
	const struct calico_ct_key *fwd_key = value;
	struct ct_iter_ctx *ictx = ctx;

	const struct calico_ct_value *rev_value = cali_ct_lookup_elem(rev_key);
	if (rev_value) {
		if (!entry_expired(rev_key, rev_value, ictx)) {
			// Race with a packet, CT entry now live again.
			goto out;
		}
	}

	ictx->num_expired++;
	cali_ct_delete_elem(fwd_key);
	cali_ct_delete_elem(rev_key);

out:
	// Always remove the entry in our scratch map.
	cali_ctc_delete_elem(key);
	return 0;
}

__attribute__((section("tc"))) int conntrack_cleanup(struct __sk_buff *skb)
{
	struct ct_iter_ctx ictx = {
		.now = bpf_ktime_get_ns(),
		.num_seen = 0,
		.num_expired = 0,
	};
	CALI_DEBUG("Starting conntrack cleanup...");

	bpf_for_each_map_elem(&cali_v4_ct3, process_ct_entry, &ictx, 0);
	bpf_for_each_map_elem(&cali_v4_ctc1, process_ctc_entry, &ictx, 0);

	CALI_DEBUG("Conntrack cleanup done: seen=%d expired=%d.", ictx.num_seen, ictx.num_expired);
	return ictx.num_seen;
}