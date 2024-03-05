// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NAT_TYPES_H__
#define __CALI_NAT_TYPES_H__

#include "bpf.h"

typedef enum calico_nat_lookup_result {
	NAT_LOOKUP_ALLOW,
	NAT_FE_LOOKUP_DROP,
	NAT_NO_BACKEND,
	NAT_EXCLUDE,
} nat_lookup_result;


struct calico_nat {
        ipv46_addr_t addr; // NBO
        __u16 port; // HBO
        __u8 protocol;
};

/* Map: NAT level one.  Dest IP, port and src IP -> ID and num backends.
 * Modified the map from HASH to LPM_TRIE. This is to drop packets outside
 * src IP range specified for Load Balancer
 */
struct __attribute__((__packed__)) calico_nat_key {
	__u32 prefixlen;
	ipv46_addr_t addr; // NBO
	__u16 port; // HBO
	__u8 protocol;
	ipv46_addr_t saddr;
	__u8 pad;
};

/* Prefix len = (dst_addr + port + protocol + src_addr) in bits. */
#define NAT_PREFIX_LEN_WITH_SRC_MATCH  (sizeof(struct calico_nat_key) - \
					sizeof(((struct calico_nat_key*)0)->prefixlen) - \
					sizeof(((struct calico_nat_key*)0)->pad))

#define NAT_PREFIX_LEN_WITH_SRC_MATCH_IN_BITS (NAT_PREFIX_LEN_WITH_SRC_MATCH * 8)

// This is used as a special ID along with count=0 to drop a packet at nat level1 lookup
#define NAT_FE_DROP_COUNT  0xffffffff

union calico_nat_lpm_key {
        struct bpf_lpm_trie_key lpm;
        struct calico_nat_key key;
};

struct calico_nat_value {
	__u32 id;
	__u32 count;
	__u32 local;
	__u32 affinity_timeo;
	__u32 flags;
};

#define NAT_FLG_EXTERNAL_LOCAL	0x1
#define NAT_FLG_INTERNAL_LOCAL	0x2
#define NAT_FLG_NAT_EXCLUDE	0x4

#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_nat_fe, cali_nat_fe, 3,
#else
CALI_MAP_NAMED(cali_v4_nat_fe, cali_nat_fe, 3,
#endif
		BPF_MAP_TYPE_LPM_TRIE,
		union calico_nat_lpm_key, struct calico_nat_value,
		64*1024, BPF_F_NO_PREALLOC)


// Map: NAT level two.  ID and ordinal -> new dest and port.

struct calico_nat_secondary_key {
	__u32 id;
	__u32 ordinal;
};

struct calico_nat_dest {
	ipv46_addr_t addr;
	__u16 port;
	__u8 pad[2];
};

#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_nat_be, cali_nat_be,,
#else
CALI_MAP_NAMED(cali_v4_nat_be, cali_nat_be,,
#endif
		BPF_MAP_TYPE_HASH,
		struct calico_nat_secondary_key, struct calico_nat_dest,
		256*1024, BPF_F_NO_PREALLOC)

struct calico_nat_affinity_key {
	struct calico_nat nat_key;
	ipv46_addr_t client_ip;
	__u32 padding;
};

struct calico_nat_affinity_val {
	struct calico_nat_dest nat_dest;
#ifdef IPVER6
	__u32 __pad;
#endif
	__u64 ts;
};


#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_nat_aff, cali_nat_aff,,
#else
CALI_MAP_NAMED(cali_v4_nat_aff, cali_nat_aff,,
#endif
		BPF_MAP_TYPE_LRU_HASH,
		struct calico_nat_affinity_key, struct calico_nat_affinity_val,
		64*1024, 0)

struct vxlanhdr {
	__be32 flags;
	__be32 vni;
};
#endif /*  __CALI_NAT_TYPES_H__ */
