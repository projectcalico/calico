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
	__u64 end_time;

	__u64 num_cleaned;
};

// process_ccq_entry processes an entry in the "cleanup queue" map.  The map
// is keyed on the reverse NAT entry's key, with the value storing the forward
// entry's key (or a zero value if the forward entry is missing).
static long process_ccq_entry(void *map, struct calico_ct_key *key, struct cali_ccq_value *value, void *ctx)
{
	bool isNatForward = false;
	struct calico_ct_key *lookup_key = key;
	struct ct_iter_ctx *ictx = ctx;

	// If NAT fwd entry, do a lookup of the rev_key.
	if (value->rev_key.protocol != 0) {
		isNatForward = true;
		lookup_key = &value->rev_key;
	}

	const struct calico_ct_value *actual_ct_value = cali_ct_lookup_elem(lookup_key);
	if (actual_ct_value) {
		if (isNatForward) {
			// If the reverse key has expired, go to delete.
			if (actual_ct_value->last_seen == value->rev_last_seen) {
			       goto delete;
			}
			return 0;
		} else {
			// This is normal or NAT reverse entry.
			if (actual_ct_value->last_seen == value->last_seen) {
				goto delete;
			}
			return 0;
		}
	} else if (isNatForward) {
		// Its a NAT forward entry but the reverse entry is not present in the CT table.
		// Set the lookup_key to the forward entry and do a lookup of the fwd entry.
		// If the timestamp's match, delete it.
		lookup_key = key;
		actual_ct_value = cali_ct_lookup_elem(lookup_key);
		// Reverse key is present, but it is already deleted from the CT table.
		if (actual_ct_value && actual_ct_value->last_seen == value->last_seen) {
			goto delete;
		}
		return 0;
	}
delete:
	// If the entry is Normal or Reverse, lookup_key points to the entry.
	// Delete the entry and if successful, increment the counter.
	// If the entry is forward, we have 2 cases,
	// Rev_entry present - lookup_key points to the reverse entry and key points to the
	// forward entry. Delete both the entries togethere.
	// Rev_entry not present - lookup_key points to the forward entry.
	// Delete it.
	if(!cali_ct_delete_elem(lookup_key)) {
		ictx->num_cleaned++;
		if (isNatForward && !cali_ct_delete_elem(key)) {
			ictx->num_cleaned++;
		}
		cali_ccq_delete_elem(key);
	}
	return 0;
}

// conntrack_cleanup is a BPF program that cleans up expired conntrack entries.
// It does a single pass of the conntrack map, checking each entry for expiry.
// Normal entries are deleted immediately if they are expired.  NAT entries are
// queued for deletion in the cali_ccq map (so that forward and reverse entries
// can be cleaned up together).
__attribute__((section("tc"))) int conntrack_cleanup(struct __sk_buff *skb)
{
	struct ct_iter_ctx ictx = {};
	bpf_skb_load_bytes(skb, 0, &ictx, sizeof(ictx));
	if (ictx.now == 0) {
		// Caller didn't provide a fixed time (as used in tests), use current
		// time.
		ictx.now = bpf_ktime_get_ns();
	}
	CALI_DEBUG("Scanning conntrack cleanup map for entries to be cleaned up...");
	bpf_for_each_map_elem(&CCQ_MAP_V, process_ccq_entry, &ictx, 0);
	// Give detailed stats back to userspace.
	ictx.end_time = bpf_ktime_get_ns();
	bpf_skb_store_bytes(skb, 0, &ictx, sizeof(ictx), 0);
	return 0;
}
