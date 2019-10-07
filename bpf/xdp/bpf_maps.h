#ifndef __CALICO_BPF_MAPS_H__
#define __CALICO_BPF_MAPS_H__

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include "../include/bpf.h"


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

// Extended map definition for compatibility with iproute2 loader.
struct bpf_map_def_extended {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 map_id;
	__u32 pinning_strategy;
	__u32 unused1;
	__u32 unused2;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_config = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = 4,
	.value_size     = sizeof(struct calico_config),
	.max_entries    = 1,
};

// Connection tracking.

struct calico_ct_key {
	__be32 src_addr; // NBO
	__be32 dst_addr; // NBO
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

enum calico_ct_type {
     CALICO_CT_TYPE_ALLOW = 0,
     CALICO_CT_TYPE_NAT = 1,
};

enum calico_egress_act {
     CALICO_EGRESS_LOCAL_EP = 0,
     CALICO_EGRESS_PASS = 1,
};

struct calico_ct_nat {
	__be32 src_addr; // NBO
	__be32 dst_addr; // NBO
    __be16 src_port; // NBO
    __be16 dst_port; // NBO
};

union calico_ct_data {
    struct calico_ct_nat ct_nat;
};

enum calico_ct_flags {
	CALICO_CT_F_WORKLOAD_APPROVED = 1<<0,
	CALICO_CT_F_HOST_APPROVED     = 1<<1,
	CALICO_CT_F_REPLY_SEEN        = 1<<2,
};

enum calico_skb_mark {
	CALICO_SKB_MARK_FROM_WORKLOAD = 0xca110000,
	CALICO_SKB_MARK_NO_TRACK      = 1<<1,
};

struct calico_ct_value {
    uint8_t ct_type;
    uint8_t flags;
    union calico_ct_data data;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_ct_map_v4 = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(struct calico_ct_key),
    .value_size     = sizeof(struct calico_ct_value),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 512000, // arbitrary
	.pinning_strategy        = 2 /* global namespace */,
};

// Policy.

struct bpf_map_def_extended __attribute__((section("maps"))) calico_failsafe_ports = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct protoport),
	.value_size     = 1,
	.max_entries    = 128,
	.map_flags      = BPF_F_NO_PREALLOC,
};

struct calico_port_range {
	uint16_t min, max;
};

struct calico_ip_match {
	__be32 addr, mask;
};

enum calico_match_type {
    CALICO_MATCH_NEGATE = 0x80,
    CALICO_MATCH_MASK_ACTION = 0x7f,

	CALICO_MATCH_ALLOW =         0,
	CALICO_MATCH_DENY =          1,

	CALICO_MATCH_PROTOCOL =      2,
	CALICO_MATCH_SRC_PORT =      4,
	CALICO_MATCH_DEST_PORT =     5,
	CALICO_MATCH_SRC_IP =        6,
	CALICO_MATCH_DEST_IP =       7,
	CALICO_MATCH_SRC_IP_SET =        8,
	CALICO_MATCH_DEST_IP_SET =       9,
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

struct calico_policy_op {
	union {
	    uint64_t ip_set_id;
		struct calico_port_range port_range;
		struct calico_ip_match ip_match;
		uint8_t protocol;
	};

	uint8_t match_type;
	uint8_t jump_no_match;
};
static_assert(sizeof(struct calico_policy_op) == 16, "Unexpected padding in struct calico_policy_op?");

const size_t CALICO_NUM_POL_OPS = 1;

struct calico_policy {
	struct calico_policy_op ops[CALICO_NUM_POL_OPS];
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_pol_do_not_track = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_bpf_lpm_trie_key),
	.value_size     = sizeof(struct calico_policy),
	.max_entries       = 65532,
	.map_flags          = BPF_F_NO_PREALLOC,
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_pol_pre_dnat = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_bpf_lpm_trie_key),
	.value_size     = sizeof(struct calico_policy),
	.max_entries       = 65533,
	.map_flags          = BPF_F_NO_PREALLOC,
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_pol_norm = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_bpf_lpm_trie_key),
	.value_size     = sizeof(struct calico_policy),
	.max_entries       = 65534,
	.map_flags          = BPF_F_NO_PREALLOC,
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_pol_aof = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_bpf_lpm_trie_key),
	.value_size     = sizeof(struct calico_policy),
	.max_entries       = 65535,
	.map_flags          = BPF_F_NO_PREALLOC,
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

// Map: Local workloads by IP

struct calico_local_ep_v4_key {
    uint8_t addr[4];
};

struct calico_local_ep_value {
    int idx;
};

struct bpf_map_def_extended __attribute__((section("maps"))) calico_local_ep_map_v4 = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(struct calico_local_ep_v4_key),
    .value_size     = sizeof(struct calico_local_ep_value),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 4096, // arbitrary
};

// Map: interface indexes.

struct bpf_map_def_extended __attribute__((section("maps"))) calico_ifaces_map = {
    .type           = BPF_MAP_TYPE_DEVMAP,
    .key_size       = sizeof(int),
    .value_size     = sizeof(int),
    // .map_flags          = BPF_F_NO_PREALLOC, not supported for this type of map
    .max_entries       = 1024, // arbitrary
};

// Map: "Main" BPF programs.

#define CALICO_PROG_ID_VETH_POST_POLICY  0

struct bpf_map_def_extended __attribute__((section("maps"))) calico_programs_map = {
    .type           = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size       = 4, // Must be exactly 4 bytes
    .value_size     = 4, // Must be exactly 4 bytes
    .max_entries       = 2048,
};

// Map: MAC switch.

struct calico_mac_sw_value  {
    uint8_t new_src[6];
    uint8_t new_dst[6];
    uint32_t flags;
    uint32_t dst_iface;
} __attribute__((packed));

#define CALICO_MAC_SW_FLAG_INGRESS 1

struct bpf_map_def_extended __attribute__((section("maps"))) calico_mac_sw_map = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = 4,
    .value_size     = sizeof(struct calico_mac_sw_value),
    .map_flags          = BPF_F_NO_PREALLOC,
    .max_entries       = 8192, // arbitrary
	.pinning_strategy = 2,
};

#endif /* __CALICO_BPF_MAPS_H__ */
