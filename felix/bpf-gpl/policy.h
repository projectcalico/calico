// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_POLICY_H__
#define __CALI_POLICY_H__

enum calico_policy_result {
	CALI_POL_NO_MATCH,
	CALI_POL_ALLOW,
	CALI_POL_DENY,
};

struct port_range {
       __u64 ip_set_id;
       __u16 min, max;
};

struct cidr {
       __be32 mask, addr;
};

// IP sets, all stored in one big map with a prefix to identify the set.

// WARNING: must be kept in sync with the definitions in bpf/polprog/pol_prog_builder.go.
// WARNING: must be kept in sync with the definitions in bpf/ipsets/map.go.
struct ip_set_key {
	__u32 mask;
	__be64 set_id;
	ipv46_addr_t addr;
	__u16 port;
	__u8 protocol;
	__u8 pad;
} __attribute__((packed));

union ip_set_lpm_key {
	struct bpf_lpm_trie_key lpm;
	struct ip_set_key ip;
};

#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_ip_sets, cali_ip_sets,,
#else
CALI_MAP_NAMED(cali_v4_ip_sets, cali_ip_sets,,
#endif
	BPF_MAP_TYPE_LPM_TRIE,
	union ip_set_lpm_key,
	__u32,
	1024*1024,
	BPF_F_NO_PREALLOC)

#define RULE_START(id)

#define RULE_END(id, action) \
	goto action; /* Reach here if the rule matched. */ \
	rule_no_match_ ## id: do {;} while (false)


#endif /* __CALI_POLICY_H__ */
