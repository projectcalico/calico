#ifndef __CALICO_CONNTRACK_H__
#define __CALICO_CONNTRACK_H__

#import "bpf.h"

// Connection tracking.

struct calico_ct_key {
	__be32 src_addr; // NBO
	__be32 dst_addr; // NBO
    uint16_t src_port; // HBO
    uint16_t dst_port; // HBO
    uint8_t protocol;
} __attribute__((packed));


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

#endif /* __CALICO_CONNTRACK_H__ */
