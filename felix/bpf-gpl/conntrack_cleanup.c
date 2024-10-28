// Project Calico BPF dataplane programs.
// Copyright (c) 2024 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <stdbool.h>

#define CALI_LOG(fmt, ...) bpf_log("CT-CLEANER------: " fmt, ## __VA_ARGS__)
#include "log.h"

#include "conntrack_cleanup.h"

const volatile struct cali_ct_cleanup_globals __globals;

// Context for the conntrack map iteration functions.
//
// WARNING: this struct is returned to user space as the result of the BPF
// program and so must be kept in sync with the equivalent struct in
// bpf_scanner.go.
struct ct_iter_ctx {
	__u64 now;
	__u64 num_seen;
	__u64 num_expired;
	__u64 end_time;
};

// sub_age calculates now-then assuming that the difference is less than
// 1<<63.  Values larger than that are assumed to have wrapped (then>now) and
// 0 is returned in that case.
static __u64 sub_age(__u64 now, __u64 then) {
	__u64 age = now - then;
	if (age > (1ull<<63)) {
		// Wrapped, assume that means then > now.
		return 0;
	}
	return age;
}

// max_age returns the maximum age for the given conntrack "tracking" entry.
static __u64 calculate_max_age(const struct calico_ct_key *key, const struct calico_ct_value *value, struct ct_iter_ctx *ctx)
{
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
	return max_age;
}

static bool entry_expired(const struct calico_ct_key *key, const struct calico_ct_value *value, struct ct_iter_ctx *ctx)
{
	__u64 age = sub_age(ctx->now, value->last_seen);
	__u64 max_age = calculate_max_age(key, value, ctx);
	return age > max_age;
}

// process_ct_entry callback function for the conntrack map iteration.  Checks
// the entry for expiry.  Expired normal entries are deleted inline.  Expired
// NAT entries are queued for deletion in the cali_ccq map.
static long process_ct_entry(void *map, const void *key, void *value, void *ctx)
{
	const struct calico_ct_key *ct_key = key;
	struct calico_ct_value *ct_value = value;
	struct calico_ct_value *rev_value;
	struct ct_iter_ctx *ictx = ctx;

	__u64 age = sub_age(ictx->now, ct_value->last_seen);
	__u64 age_s = age/1000000000ull;
#ifdef IPVER6
	CALI_DEBUG("Checking: proto=%d [%pI6]:%d", ct_key->protocol, &ct_key->addr_a, ct_key->port_a);
	CALI_DEBUG("  <->[%pI6]:%d age=%ds", &ct_key->addr_b, ct_key->port_b, age_s);
#else
	CALI_DEBUG("Checking: proto=%d %pI4:%d", ct_key->protocol, &ct_key->addr_a, ct_key->port_a);
	CALI_DEBUG("  <->%pI4:%d age=%ds", &ct_key->addr_b, ct_key->port_b, age_s);
#endif

	ictx->num_seen++;

	__u64 max_age, max_age_s;

	switch (ct_value->type) {
	case CALI_CT_TYPE_NORMAL:
		// Non-NAT entry, we only need to look at this entry to determine if it
		// has expired.
		max_age = calculate_max_age(ct_key, ct_value, ictx);
		max_age_s = max_age/1000000000ull;
		if (age > max_age) {
			CALI_DEBUG("  EXPIRED: normal entry (max_age=%d).", max_age_s);
			if (cali_ct_delete_elem(ct_key) == 0) {
				ictx->num_expired++;
			}
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
				CALI_DEBUG("  INVALID: Forward NAT entry with no reverse entry, ignoring due to creation grace period.");
				break;
			}

			// Entry is not fresh so it looks invalid.  Clean it up.
			CALI_DEBUG("  INVALID: Forward NAT entry with no reverse entry, cleaning up.");
			if (cali_ct_delete_elem(ct_key) == 0) {
				ictx->num_expired++;
			}
			break;
		}

		// Got a reverse entry, which has the overall "last_seen" for the
		// connection.  Check if this entry has expired.
		age = sub_age(ictx->now, rev_value->last_seen);
		age_s = age/1000000000ull;
#ifdef IPVER6
		CALI_DEBUG("  Reverse NAT: proto=%d [%pI6]:%d", ct_key->protocol, &ct_value->nat_rev_key.addr_a, ct_value->nat_rev_key.port_a);
		CALI_DEBUG("    <->[%pI6]:%d age=%ds", &ct_value->nat_rev_key.addr_b, ct_value->nat_rev_key.port_b, age_s);
#else
		CALI_DEBUG("  Reverse NAT: proto=%d %pI4:%d", ct_key->protocol, &ct_value->nat_rev_key.addr_a, ct_value->nat_rev_key.port_a);
		CALI_DEBUG("    <->%pI4:%d age=%ds", &ct_value->nat_rev_key.addr_b, ct_value->nat_rev_key.port_b, age_s);
#endif

		max_age = calculate_max_age(&ct_value->nat_rev_key, rev_value, ictx);
		max_age_s = max_age/1000000000ull;
		if (age > max_age) {
			// Expired, mark the entries for cleanup.  We can't just delete
			// them now because it's not safe to delete _other_ entries from
			// the map while iterating.
			CALI_DEBUG("  EXPIRED: forward/reverse NAT entries (max_age=%d), queuing for deletion.", max_age_s);
			if (cali_ccq_update_elem(&ct_value->nat_rev_key, ct_key, BPF_ANY)) {
				CALI_DEBUG("  Failed to queue entry, queue full?");
			}
		}

		break;
	case CALI_CT_TYPE_NAT_REV:
		// One half of a NAT entry.  The "reverse" entry is updated when we see
		// traffic in either direction.
		if (entry_expired(ct_key, ct_value, ictx)) {
			// Reverse entry has expired, but the reverse entry doesn't have a
			// link to the forward entry so we write a dummy key and use
			// BPF_NOEXIST to avoid overwriting a real key.
			struct calico_ct_key dummy_key = {};
			long rc = cali_ccq_update_elem(ct_key, &dummy_key, BPF_NOEXIST);
			if (rc) {
				CALI_DEBUG("  EXPIRED: Reverse NAT entry, already in queue or queue full (rc=%d).", rc);
			} else {
				CALI_DEBUG("  EXPIRED: Reverse NAT entry, queued for deletion. (Forward NAT entry not yet seen.)");
			}
		}
		break;
	}

	return 0;
}

// process_ccq_entry processes an entry in the "cleanup queue" map.  The map
// is keyed on the reverse NAT entry's key, with the value storing the forward
// entry's key (or a zero value if the forward entry is missing).
static long process_ccq_entry(void *map, const void *key, void *value, void *ctx)
{
	// Map stores mapping from reverse key to forward key (if known).
	const struct calico_ct_key *rev_key = key;
	const struct calico_ct_key *fwd_key = value;
	struct ct_iter_ctx *ictx = ctx;

	// It might be a few ms since we queued this entry, recheck it to make sure
	// it is still expired.
	const struct calico_ct_value *rev_value = cali_ct_lookup_elem(rev_key);
	if (rev_value) {
		__u64 age = sub_age(ictx->now, rev_value->last_seen);
		__u64 age_s = age/1000000000ull;
#ifdef IPVER6
		CALI_DEBUG("Re-checking: proto=%d [%pI6]:%d", rev_key->protocol, &rev_key->addr_a, rev_key->port_a);
		CALI_DEBUG("  <->[%pI6]:%d age=%ds", &rev_key->addr_b, rev_key->port_b, age_s);
#else
		CALI_DEBUG("Re-checking: proto=%d %pI4:%d", rev_key->protocol, &rev_key->addr_a, rev_key->port_a);
		CALI_DEBUG("  <->%pI4:%d age=%ds", &rev_key->addr_b, rev_key->port_b, age_s);
#endif
		__u64 max_age = calculate_max_age(rev_key, rev_value, ictx);
		__u64 max_age_s = max_age/1000000000ull;
		if (age < max_age) {
			// Race with a packet, CT entry now live again.
			CALI_DEBUG("  RESURRECTED: entry no longer expired (max_age=%d).", max_age_s);
			goto out;
		}
		CALI_DEBUG("  EXPIRED: cleaning up forward/reverse entries (max_age=%d).", max_age_s);
	} else {
		CALI_DEBUG("  MISSING: lookup failed.");
	}

	// Still expired, delete both entries.  The forward key might be a dummy
	// all-zeros key but we know that key won't exist so we just let
	// cali_ct_delete_elem handle that.
	if (cali_ct_delete_elem(fwd_key) == 0) {
		ictx->num_expired++;
	}
	if (cali_ct_delete_elem(rev_key) == 0) {
		ictx->num_expired++;
	}

out:
	// Always remove the entry in our scratch map.
	cali_ccq_delete_elem(key);
	return 0;
}

// conntrack_cleanup is a BPF program that cleans up expired conntrack entries.
// It does a single pass of the conntrack map, checking each entry for expiry.
// Normal entries are deleted immediately if they are expired.  NAT entries are
// queued for deletion in the cali_ccq map (so that forward and reverse entries
// can be cleaned up together).
__attribute__((section("tc"))) int conntrack_cleanup(struct __sk_buff *skb)
{
	struct ct_iter_ctx ictx = {
		.now = bpf_ktime_get_ns(),
		.num_seen = 0,
		.num_expired = 0,
	};

	CALI_DEBUG("Scanning conntrack map for expired non-NAT entries...");
	bpf_for_each_map_elem(&CT_MAP_V, process_ct_entry, &ictx, 0);
	CALI_DEBUG("First pass complete, expired %d entries so far of %d total.", ictx.num_expired, ictx.num_seen);
	CALI_DEBUG("Processing NAT entries...");
	bpf_for_each_map_elem(&CCQ_MAP_V, process_ccq_entry, &ictx, 0);
	CALI_DEBUG("Conntrack cleanup complete: expired %d entries of %d total.", ictx.num_expired, ictx.num_seen);

	// Give detailed stats back to userspace.
	ictx.end_time = bpf_ktime_get_ns();
	bpf_skb_store_bytes(skb, 0, &ictx, sizeof(ictx), 0);

	return ictx.num_seen;
}
