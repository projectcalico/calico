#ifndef __CALICO_BPF_MAPS_H__
#define __CALICO_BPF_MAPS_H__

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include "../include/bpf.h"
#include "../include/conntrack.h"

struct protoport {
	__u16 proto;
	__u16 port;
};

// Configuration
struct calico_config {
	uint32_t debug_on;
	uint32_t untracked_on;
	uint32_t pre_dnat_on;
	uint32_t nat_on;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_config = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = 4,
	.value_size     = sizeof(struct calico_config),
	.max_entries    = 1,
};

enum calico_skb_mark {
	// TODO allocate marks from the mark pool.
	CALICO_SKB_MARK_FROM_WORKLOAD = 0xca110000,
	CALICO_SKB_MARK_FROM_WORKLOAD_MASK = 0xffff0000,
	CALICO_SKB_MARK_NO_TRACK      = 1<<1,
};

enum calico_reason {
	CALICO_REASON_UNKNOWN = 0x00,
	CALICO_REASON_SHORT = 0x01,
	CALICO_REASON_NOT_IP = 0xea,
	CALICO_REASON_FAILSAFE = 0xfa,
	CALICO_REASON_DNT = 0xd0,
	CALICO_REASON_PREDNAT = 0xd1,
	CALICO_REASON_POL = 0xbe,
	CALICO_REASON_CT = 0xc0,
	CALICO_REASON_CT_NAT = 0xc1,
	CALICO_REASON_CSUM_FAIL= 0xcf,
};

// IP sets, all stored in one big map with a prefix to identify the set.

struct ip4setkey {
	__u32 mask;
	__be64 set_id;
	__be32 addr;
	__u16 port;
	__u8 protocol;
	__u8 pad;
} __attribute__((packed));

union ip4_set_bpf_lpm_trie_key {
	struct bpf_lpm_trie_key lpm;
	struct ip4setkey ip;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_ip_sets = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_set_bpf_lpm_trie_key),
	.value_size     = sizeof(uint32_t),
	.max_entries       = 1024*1024,
	.map_flags          = BPF_F_NO_PREALLOC,
	.pinning_strategy        = 2 /* global namespace */,
};

// Map: NAT level one.  Dest IP and port -> ID and num backends.

struct calico_nat_v4_key {
    uint32_t addr; // NBO
    uint16_t port; // HBO
    uint8_t protocol;
};

struct calico_nat_v4_value {
    uint32_t id;
    uint32_t count;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_nat_map_v4 = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(struct calico_nat_v4_key),
    .value_size     = sizeof(struct calico_nat_v4_value),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 511000, // arbitrary
};

// Map: NAT level two.  ID and ordinal -> new dest and port.

struct calico_nat_secondary_v4_key {
    uint32_t id;
    uint32_t ordinal;
};

struct calico_nat_secondary_v4_value {
    uint32_t addr;
    uint16_t port;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_nat_secondary_map_v4 = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(struct calico_nat_secondary_v4_key),
    .value_size     = sizeof(struct calico_nat_secondary_v4_value),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 510000, // arbitrary
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_local_ips = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint32_t),
    .value_size     = sizeof(uint32_t),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 1024, // arbitrary
};

#endif /* __CALICO_BPF_MAPS_H__ */
