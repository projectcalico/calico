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

#ifndef __CALI_NAT_TYPES_H__
#define __CALI_NAT_TYPES_H__

#include "bpf.h"

typedef enum calico_nat_lookup_result {
	NAT_LOOKUP_ALLOW,
	NAT_FE_LOOKUP_DROP,
	NAT_NO_BACKEND,
} nat_lookup_result;


struct calico_nat_v4 {
        __u32 addr; // NBO
        __u16 port; // HBO
        __u8 protocol;
};

/* Map: NAT level one.  Dest IP, port and src IP -> ID and num backends.
 * Modified the map from HASH to LPM_TRIE. This is to drop packets outside
 * src IP range specified for Load Balancer
 */
struct __attribute__((__packed__)) calico_nat_v4_key {
	__u32 prefixlen;
	__u32 addr; // NBO
	__u16 port; // HBO
	__u8 protocol;
	__u32 saddr;
	__u8 pad;
};

/* Prefix len = (dst_addr + port + protocol + src_addr) in bits. */
#define NAT_PREFIX_LEN_WITH_SRC_MATCH  (sizeof(struct calico_nat_v4_key) - \
					sizeof(((struct calico_nat_v4_key*)0)->prefixlen) - \
					sizeof(((struct calico_nat_v4_key*)0)->pad))

#define NAT_PREFIX_LEN_WITH_SRC_MATCH_IN_BITS (NAT_PREFIX_LEN_WITH_SRC_MATCH * 8)

// This is used as a special ID along with count=0 to drop a packet at nat level1 lookup
#define NAT_FE_DROP_COUNT  0xffffffff

union calico_nat_v4_lpm_key {
        struct bpf_lpm_trie_key lpm;
        struct calico_nat_v4_key key;
};

struct calico_nat_v4_value {
	__u32 id;
	__u32 count;
	__u32 local;
	__u32 affinity_timeo;
};

CALI_MAP(cali_v4_nat_fe, 2,
		BPF_MAP_TYPE_LPM_TRIE,
		union calico_nat_v4_lpm_key, struct calico_nat_v4_value,
		511000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)


// Map: NAT level two.  ID and ordinal -> new dest and port.

struct calico_nat_secondary_v4_key {
	__u32 id;
	__u32 ordinal;
};

struct calico_nat_dest {
	__u32 addr;
	__u16 port;
	__u8 pad[2];
};

CALI_MAP_V1(cali_v4_nat_be,
		BPF_MAP_TYPE_HASH,
		struct calico_nat_secondary_v4_key, struct calico_nat_dest,
		510000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

struct calico_nat_v4_affinity_key {
	struct calico_nat_v4 nat_key;
	__u32 client_ip;
	__u32 padding;
};

struct calico_nat_v4_affinity_val {
	struct calico_nat_dest nat_dest;
	__u64 ts;
};


CALI_MAP_V1(cali_v4_nat_aff,
		BPF_MAP_TYPE_LRU_HASH,
		struct calico_nat_v4_affinity_key, struct calico_nat_v4_affinity_val,
		510000, 0, MAP_PIN_GLOBAL)

struct vxlanhdr {
	__be32 flags;
	__be32 vni;
};
#endif /*  __CALI_NAT_TYPES_H__ */
