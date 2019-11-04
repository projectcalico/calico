#ifndef __CALI_BPF_MAPS_H__
#define __CALI_BPF_MAPS_H__

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

enum calico_reason {
	CALI_REASON_UNKNOWN = 0x00,
	CALI_REASON_SHORT = 0x01,
	CALI_REASON_NOT_IP = 0xea,
	CALI_REASON_FAILSAFE = 0xfa,
	CALI_REASON_DNT = 0xd0,
	CALI_REASON_PREDNAT = 0xd1,
	CALI_REASON_POL = 0xbe,
	CALI_REASON_CT = 0xc0,
	CALI_REASON_BYPASS = 0xbb,
	CALI_REASON_CT_NAT = 0xc1,
	CALI_REASON_CSUM_FAIL= 0xcf,
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

struct bpf_map_def_extended __attribute__((section("maps"))) calico_local_ips = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint32_t),
    .value_size     = sizeof(uint32_t),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 1024, // arbitrary
};

#endif /* __CALI_BPF_MAPS_H__ */
