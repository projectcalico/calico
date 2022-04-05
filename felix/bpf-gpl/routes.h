// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

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
	CALI_RT_UNKNOWN     = 0x00,
	CALI_RT_IN_POOL     = 0x01,
	CALI_RT_NAT_OUT     = 0x02,
	CALI_RT_WORKLOAD    = 0x04,
	CALI_RT_LOCAL       = 0x08,
	CALI_RT_HOST        = 0x10,
	CALI_RT_SAME_SUBNET = 0x20,
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

CALI_MAP_V1(cali_v4_routes,
		BPF_MAP_TYPE_LPM_TRIE,
		union cali_rt_lpm_key, struct cali_rt,
		256*1024, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE struct cali_rt *cali_rt_lookup(__be32 addr)
{
	union cali_rt_lpm_key k;
	k.key.prefixlen = 32;
	k.key.addr = addr;
	return cali_v4_routes_lookup_elem(&k);
}

static CALI_BPF_INLINE enum cali_rt_flags cali_rt_lookup_flags(__be32 addr)
{
	struct cali_rt *rt = cali_rt_lookup(addr);
	if (!rt) {
		return CALI_RT_UNKNOWN;
	}
	return rt->flags;
}

#define cali_rt_is_local(rt)	((rt)->flags & CALI_RT_LOCAL)
#define cali_rt_is_host(rt)	((rt)->flags & CALI_RT_HOST)
#define cali_rt_is_workload(rt)	((rt)->flags & CALI_RT_WORKLOAD)

#define cali_rt_flags_local_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST)) == (CALI_RT_LOCAL | CALI_RT_HOST))
#define cali_rt_flags_local_workload(t) (((t) & CALI_RT_LOCAL) && ((t) & CALI_RT_WORKLOAD))
#define cali_rt_flags_remote_workload(t) (!((t) & CALI_RT_LOCAL) && ((t) & CALI_RT_WORKLOAD))
#define cali_rt_flags_remote_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST)) == CALI_RT_HOST)

static CALI_BPF_INLINE bool rt_addr_is_local_host(__be32 addr)
{
	return  cali_rt_flags_local_host(cali_rt_lookup_flags(addr));
}

static CALI_BPF_INLINE bool rt_addr_is_remote_host(__be32 addr)
{
	return  cali_rt_flags_remote_host(cali_rt_lookup_flags(addr));
}

#endif /* __CALI_ROUTES_H__ */
