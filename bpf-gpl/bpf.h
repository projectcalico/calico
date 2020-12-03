// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __CALI_BPF_H__
#define __CALI_BPF_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>   /* For bpf_xxx helper functions. */
#include <bpf_endian.h>    /* For bpf_ntohX etc. */
#include <stddef.h>
#include <linux/ip.h>

#define CALI_BPF_INLINE inline __attribute__((always_inline))

#define BPF_REDIR_EGRESS 0
#define BPF_REDIR_INGRESS 1

/* Extended map definition for compatibility with iproute2 loader. */
struct bpf_map_def_extended {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 map_id;
#ifndef __BPFTOOL_LOADER__
	__u32 pinning_strategy;
	__u32 unused1;
	__u32 unused2;
#endif
};

/* These constants must be kept in sync with the calculate-flags script. */
#define CALI_TC_HOST_EP		(1<<0)
#define CALI_TC_INGRESS		(1<<1)
#define CALI_TC_TUNNEL		(1<<2)
#define CALI_CGROUP		(1<<3)
#define CALI_TC_DSR		(1<<4)
#define CALI_TC_WIREGUARD	(1<<5)

#ifndef CALI_COMPILE_FLAGS
#define CALI_COMPILE_FLAGS 0
#endif

#define CALI_F_INGRESS ((CALI_COMPILE_FLAGS) & CALI_TC_INGRESS)
#define CALI_F_EGRESS  (!CALI_F_INGRESS)

#define CALI_F_HEP     	 ((CALI_COMPILE_FLAGS) & CALI_TC_HOST_EP)
#define CALI_F_WEP     	 (!CALI_F_HEP)
#define CALI_F_TUNNEL  	 ((CALI_COMPILE_FLAGS) & CALI_TC_TUNNEL)
#define CALI_F_WIREGUARD ((CALI_COMPILE_FLAGS) & CALI_TC_WIREGUARD)

#define CALI_F_FROM_HEP (CALI_F_HEP && CALI_F_INGRESS)
#define CALI_F_TO_HEP   (CALI_F_HEP && !CALI_F_INGRESS)

#define CALI_F_FROM_WEP (CALI_F_WEP && CALI_F_EGRESS)
#define CALI_F_TO_WEP   (CALI_F_WEP && CALI_F_INGRESS)

#define CALI_F_TO_HOST       (CALI_F_FROM_HEP || CALI_F_FROM_WEP)
#define CALI_F_FROM_HOST     (!CALI_F_TO_HOST)
#define CALI_F_L3            ((CALI_F_TO_HEP && CALI_F_TUNNEL) || CALI_F_WIREGUARD)
#define CALI_F_IPIP_ENCAPPED (CALI_F_INGRESS && CALI_F_TUNNEL)
#define CALI_F_WG_INGRESS    (CALI_F_INGRESS && CALI_F_WIREGUARD)

#define CALI_F_CGROUP	(((CALI_COMPILE_FLAGS) & CALI_CGROUP) != 0)
#define CALI_F_DSR	(CALI_COMPILE_FLAGS & CALI_TC_DSR)

#define CALI_RES_REDIR_BACK	(TC_ACT_VALUE_MAX + 100) /* packet should be sent back the same iface */
#define CALI_RES_REDIR_IFINDEX	(TC_ACT_VALUE_MAX + 101) /* packet should be sent straight to
							  * state->ct_result->ifindex_fwd
							  */

#define FIB_ENABLED (!CALI_F_L3 && CALI_FIB_LOOKUP_ENABLED && CALI_F_TO_HOST)

#define COMPILE_TIME_ASSERT(expr) {typedef char array[(expr) ? 1 : -1];}
static CALI_BPF_INLINE void __compile_asserts(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-local-typedef"
	/* Either CALI_CGROUP is set or the other TC flags */
	COMPILE_TIME_ASSERT(
		CALI_COMPILE_FLAGS == 0 ||
		!!(CALI_COMPILE_FLAGS & CALI_CGROUP) !=
		!!(CALI_COMPILE_FLAGS & (CALI_TC_HOST_EP | CALI_TC_INGRESS | CALI_TC_TUNNEL | CALI_TC_DSR))
	);
	COMPILE_TIME_ASSERT(!CALI_F_DSR || (CALI_F_DSR && CALI_F_FROM_WEP) || (CALI_F_DSR && CALI_F_HEP));
	COMPILE_TIME_ASSERT(CALI_F_TO_HOST || CALI_F_FROM_HOST);
#pragma clang diagnostic pop
}

enum calico_skb_mark {
	// TODO allocate marks from the mark pool.
	CALI_MARK_CALICO                     = 0xc0000000,
	CALI_MARK_CALICO_MASK                = 0xf0000000,
	CALI_SKB_MARK_SEEN                   = CALI_MARK_CALICO      | 0x01000000,
	CALI_SKB_MARK_SEEN_MASK              = CALI_MARK_CALICO_MASK | CALI_SKB_MARK_SEEN,
	CALI_SKB_MARK_BYPASS                 = CALI_SKB_MARK_SEEN    | 0x02000000,
	CALI_SKB_MARK_BYPASS_FWD             = CALI_SKB_MARK_BYPASS  | 0x00300000,
	CALI_SKB_MARK_BYPASS_FWD_SRC_FIXUP   = CALI_SKB_MARK_BYPASS  | 0x00500000,
	CALI_SKB_MARK_SKIP_RPF               = CALI_SKB_MARK_BYPASS  | 0x00400000,
	CALI_SKB_MARK_NAT_OUT                = CALI_SKB_MARK_BYPASS  | 0x00800000,
};

#define ip_is_dnf(ip) ((ip)->frag_off & bpf_htons(0x4000))
#define ip_frag_no(ip) ((ip)->frag_off & bpf_htons(0x1fff))

static CALI_BPF_INLINE void ip_dec_ttl(struct iphdr *ip)
{
	ip->ttl--;
	/* since we change only a single byte, as per RFC-1141 we an adjust it
	 * inline without helpers.
	 */
	__u32 sum = ip->check;
	sum += bpf_htons(0x0100);
	ip->check = (__be16) (sum + (sum >> 16));
}

#define ip_ttl_exceeded(ip) (CALI_F_TO_HOST && !CALI_F_TUNNEL && (ip)->ttl <= 1)

#define CALI_CONFIGURABLE_DEFINE(name, pattern)							\
static CALI_BPF_INLINE __be32 cali_configurable_##name()					\
{												\
	__u32 ret;										\
	asm("%0 = " #pattern ";" : "=r"(ret) /* output */ : /* no inputs */ : /* no clobber */);\
	return ret;										\
}

#define CALI_CONFIGURABLE(name)	cali_configurable_##name()

CALI_CONFIGURABLE_DEFINE(host_ip, 0x54534f48) /* be 0x54534f48 = ASCII(HOST) */
CALI_CONFIGURABLE_DEFINE(tunnel_mtu, 0x55544d54) /* be 0x55544d54 = ASCII(TMTU) */

#define HOST_IP		CALI_CONFIGURABLE(host_ip)
#define TUNNEL_MTU 	CALI_CONFIGURABLE(tunnel_mtu)

#define MAP_PIN_GLOBAL	2

#ifndef __BPFTOOL_LOADER__
#define CALI_MAP_TC_EXT_PIN(pin)	.pinning_strategy = pin,
#else
#define CALI_MAP_TC_EXT_PIN(pin)
#endif

#define map_symbol(name, ver) name##ver

#define MAP_LOOKUP_FN(name, ver) \
static CALI_BPF_INLINE void * name##_lookup_elem(const void* key)	\
{									\
	return bpf_map_lookup_elem(&map_symbol(name, ver), key);	\
}

#define MAP_UPDATE_FN(name, ver) \
static CALI_BPF_INLINE int name##_update_elem(const void* key, const void* value, __u64 flags)\
{										\
	return bpf_map_update_elem(&map_symbol(name, ver), key, value, flags);	\
}

#define MAP_DELETE_FN(name, ver) \
static CALI_BPF_INLINE int name##_delete_elem(const void* key)	\
{									\
	return bpf_map_delete_elem(&map_symbol(name, ver), key);	\
}

#define CALI_MAP(name, ver,  map_type, key_type, val_type, size, flags, pin) 		\
struct bpf_map_def_extended __attribute__((section("maps"))) map_symbol(name, ver) = {	\
	.type = map_type,								\
	.key_size = sizeof(key_type),							\
	.value_size = sizeof(val_type),							\
	.map_flags = flags,								\
	.max_entries = size,								\
	CALI_MAP_TC_EXT_PIN(pin)							\
};											\
											\
	MAP_LOOKUP_FN(name, ver)							\
	MAP_UPDATE_FN(name, ver)							\
	MAP_DELETE_FN(name, ver)

#define CALI_MAP_V1(name, map_type, key_type, val_type, size, flags, pin) 	\
		CALI_MAP(name,, map_type, key_type, val_type, size, flags, pin)


#endif /* __CALI_BPF_H__ */
