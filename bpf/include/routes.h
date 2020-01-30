// Copyright (c) 2019 Tigera, Inc. All rights reserved.

#ifndef __CALI_ROUTES_H__
#define __CALI_ROUTES_H__

#include <linux/in.h>
#include "bpf.h"

// Map: Routes

struct cali_rt_key {
	__u32 prefixlen;
	__be32 addr; // NBO
};

union cali_rt_lpm_key {
	struct bpf_lpm_trie_key lpm;
	struct cali_rt_key key;
};

enum cali_rt_flags {
	CALI_RT_UNKNOWN  = 0x00,
	CALI_RT_IN_POOL  = 0x01,
	CALI_RT_NAT_OUT  = 0x02,
	CALI_RT_WORKLOAD = 0x04,
	CALI_RT_LOCAL    = 0x08,
	CALI_RT_HOST     = 0x10,
};

struct cali_rt {
	__u32 flags; /* enum cali_rt_flags */
	union {
		// IP encap next hop for remote workload routes.
		__u32 next_hop;
		// Interface index for local workload routes.
		__u32 if_index;
	};
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_routes = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union cali_rt_lpm_key),
	.value_size     = sizeof(struct cali_rt),
	.max_entries    = 1024*1024,
	.map_flags      = BPF_F_NO_PREALLOC,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy        = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE struct cali_rt *cali_rt_lookup(__be32 addr)
{
	union cali_rt_lpm_key k;
	k.key.prefixlen = 32;
	k.key.addr = addr;
	return bpf_map_lookup_elem(&cali_v4_routes, &k);
}

static CALI_BPF_INLINE enum cali_rt_flags cali_rt_lookup_flags(__be32 addr)
{
	struct cali_rt *rt = cali_rt_lookup(addr);
	if (!rt) {
		return CALI_RT_UNKNOWN;
	}
	return rt->flags;
}

#define  cali_rt_is_local(rt) ((rt)->flags & CALI_RT_LOCAL)
#define  cali_rt_is_host(rt) ((rt)->flags & CALI_RT_HOST)

#define  cali_rt_flags_local_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST)) == (CALI_RT_LOCAL | CALI_RT_HOST))
#define  cali_rt_flags_local_workload(t) (((t) & CALI_RT_LOCAL) && ((t) & CALI_RT_WORKLOAD))
#define  cali_rt_flags_remote_workload(t) (!((t) & CALI_RT_LOCAL) && ((t) & CALI_RT_WORKLOAD))

#endif /* __CALI_ROUTES_H__ */
