// Copyright (c) 2019 Tigera, Inc. All rights reserved.

#ifndef __CALI_ROUTES_H__
#define __CALI_ROUTES_H__

#include <linux/in.h>
#include "bpf.h"

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

struct calico_route {
	__u32 type; /* enum calico_route_type */
	__u32 next_hop;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_routes = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union calico_route_lpm_key),
	.value_size     = sizeof(struct calico_route),
	.max_entries    = 1024*1024,
	.map_flags      = BPF_F_NO_PREALLOC,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy        = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE struct calico_route *cali_rt_lookup(__be32 addr)
{
	union calico_route_lpm_key k;
	k.key.prefixlen = 32;
	k.key.addr = addr;
	return bpf_map_lookup_elem(&cali_v4_routes, &k);
}

static CALI_BPF_INLINE enum calico_route_type cali_rt_lookup_type(__be32 addr)
{
	struct calico_route *rt = cali_rt_lookup(addr);
	if (!rt) {
		return CALI_RT_UNKNOWN;
	}
	return rt->type;
}

static CALI_BPF_INLINE bool cali_rt_is_local(struct calico_route *rt)
{
	return (rt->type == CALI_RT_LOCAL_HOST) || (rt->type == CALI_RT_LOCAL_WORKLOAD);
}

#endif /* __CALI_ROUTES_H__ */
