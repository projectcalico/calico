#ifndef __CALI_ROUTES_H__
#define __CALI_ROUTES_H__

#include <linux/in.h>
#import "bpf.h"

// Map: Routes

struct calico_route_key {
	__u32 prefixlen;
	__be32 addr; // NBO
};

union calico_route_key_u {
	struct bpf_lpm_trie_key lpm;
	struct calico_route_key key;
};

enum calico_route_type {
	CALI_RT_UNKNOWN = 0,
	CALI_RT_REMOTE_WORKLOAD = 1,
	CALI_RT_REMOTE_HOST = 2,
	CALI_RT_LOCAL_HOST = 3,
	CALI_RT_LOCAL_WORKLOAD = 4,
};

struct calico_route_value {
	__u32 type; /* enum calico_route_type */
	__u32 next_hop;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_routes = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union calico_route_key_u),
	.value_size     = sizeof(struct calico_route_value),
	.max_entries    = 1024*1024,
	.map_flags      = BPF_F_NO_PREALLOC,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy        = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE struct calico_route_value *calico_lookup_route(__be32 addr) {
	union calico_route_key_u k;
	k.key.prefixlen = 32;
	k.key.addr = addr;
	return bpf_map_lookup_elem(&cali_routes, &k);
}

static CALI_BPF_INLINE enum calico_route_type calico_lookup_route_type(__be32 addr) {
	struct calico_route_value *rt_val = calico_lookup_route(addr);
	if (!rt_val) {
		return CALI_RT_UNKNOWN;
	}
	return rt_val->type;
}

#endif /* __CALI_ROUTES_H__ */
