// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ROUTES_H__
#define __CALI_ROUTES_H__

#include <linux/in.h>
#include "bpf.h"

// Map: Routes

struct cali_rt_key {
	__u32 prefixlen;
	ipv46_addr_t addr; // NBO
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
	CALI_RT_TUNNELED    = 0x40,
	CALI_RT_NO_DSR      = 0x80,
};

struct cali_rt {
	__u32 flags; /* enum cali_rt_flags */
	union {
		// IP encap next hop for remote workload routes.
		ipv46_addr_t next_hop;
		// Interface index for local workload routes.
		__u32 if_index;
	};
};

#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_routes, cali_routes,,
#else
CALI_MAP_NAMED(cali_v4_routes, cali_routes,,
#endif
		BPF_MAP_TYPE_LPM_TRIE,
		union cali_rt_lpm_key, struct cali_rt,
		256*1024, BPF_F_NO_PREALLOC)

static CALI_BPF_INLINE struct cali_rt *cali_rt_lookup(ipv46_addr_t *addr)
{
	union cali_rt_lpm_key k;
#ifdef IPVER6
	k.key.prefixlen = 128;
#else
	k.key.prefixlen = 32;
#endif
	k.key.addr = *addr;
	return cali_routes_lookup_elem(&k);
}

static CALI_BPF_INLINE enum cali_rt_flags cali_rt_lookup_flags(ipv46_addr_t *addr)
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
#define cali_rt_is_tunneled(rt)	((rt)->flags & CALI_RT_TUNNELED)

#define cali_rt_flags_host(t) (((t) & CALI_RT_HOST) == CALI_RT_HOST)
#define cali_rt_flags_local_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST)) == (CALI_RT_LOCAL | CALI_RT_HOST))
#define cali_rt_flags_local_workload(t) (((t) & CALI_RT_LOCAL) && ((t) & CALI_RT_WORKLOAD))
#define cali_rt_flags_remote_workload(t) (!((t) & CALI_RT_LOCAL) && ((t) & CALI_RT_WORKLOAD))
#define cali_rt_flags_remote_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST)) == CALI_RT_HOST)
#define cali_rt_flags_remote_tunneled_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST | CALI_RT_TUNNELED)) == (CALI_RT_HOST | CALI_RT_TUNNELED))
#define cali_rt_flags_local_tunneled_host(t) (((t) & (CALI_RT_LOCAL | CALI_RT_HOST | CALI_RT_TUNNELED)) == (CALI_RT_LOCAL | CALI_RT_HOST | CALI_RT_TUNNELED))

static CALI_BPF_INLINE bool rt_addr_is_local_host(ipv46_addr_t *addr)
{
	return  cali_rt_flags_local_host(cali_rt_lookup_flags(addr));
}

static CALI_BPF_INLINE bool rt_addr_is_remote_host(ipv46_addr_t *addr)
{
	return  cali_rt_flags_remote_host(cali_rt_lookup_flags(addr));
}

static CALI_BPF_INLINE bool rt_addr_is_remote_tunneled_host(ipv46_addr_t *addr)
{
	return cali_rt_flags_remote_tunneled_host(cali_rt_lookup_flags(addr));
}

static CALI_BPF_INLINE bool rt_addr_is_local_tunneled_host(ipv46_addr_t *addr)
{
	return cali_rt_flags_local_tunneled_host(cali_rt_lookup_flags(addr));
}
#endif /* __CALI_ROUTES_H__ */
