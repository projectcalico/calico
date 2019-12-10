#ifndef __CALI_ROUTES_H__
#define __CALI_ROUTES_H__

#include <linux/in.h>
#import "bpf.h"

// Map: Routes

struct calico_route_key {
	__u32 prefixlen;
	__be32 addr; // NBO
};

union calico_route_lpm_key {
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

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_routes = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union calico_route_lpm_key),
	.value_size     = sizeof(struct calico_route_value),
	.max_entries    = 1024*1024,
	.map_flags      = BPF_F_NO_PREALLOC,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy        = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE struct calico_route_value *cali_rt_lookup(__be32 addr) {
	union calico_route_lpm_key k;
	k.key.prefixlen = 32;
	k.key.addr = addr;
	return bpf_map_lookup_elem(&cali_v4_routes, &k);
}

static CALI_BPF_INLINE enum calico_route_type cali_rt_lookup_type(__be32 addr) {
	struct calico_route_value *rt_val = cali_rt_lookup(addr);
	if (!rt_val) {
		return CALI_RT_UNKNOWN;
	}
	return rt_val->type;
}

static CALI_BPF_INLINE bool cali_rt_is_local(__be32 addr) {
	enum calico_route_type rt_type = cali_rt_lookup_type(addr);
	return (rt_type == CALI_RT_LOCAL_HOST) || (rt_type == CALI_RT_LOCAL_WORKLOAD);
}

#endif /* __CALI_ROUTES_H__ */
