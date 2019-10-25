// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __CALI_BPF_H__
#define __CALI_BPF_H__

#include <linux/bpf.h>
#include <bpf/libbpf.h>    // for bpftool dyn loader struct 'bpf_map_def'

#define CALI_BPF_INLINE inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be64_to_host(value) __builtin_bswap64(value)
#define host_to_be64(value) __builtin_bswap64(value)
#define be32_to_host(value) __builtin_bswap32(value)
#define host_to_be32(value) __builtin_bswap32(value)
#define be16_to_host(value) __builtin_bswap16(value)
#define host_to_be16(value) __builtin_bswap16(value)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define be64_to_host(value) (value)
#define host_to_be64(value) (value)
#define be32_to_host(value) (value)
#define host_to_be32(value) (value)
#define be16_to_host(value) (value)
#define host_to_be16(value) (value)
#else
#error "COMPILER ERROR: cannot determine target endianness."
#endif


/*
 * BPF helper function stubs
 */

#define MAKEFUNC(ret_type,fname,...) \
	static ret_type (*bpf_ ## fname)(__VA_ARGS__) = (void*) BPF_FUNC_ ## fname;

#define BPF_REDIR_EGRESS 0
#define BPF_REDIR_INGRESS 1
MAKEFUNC(int, msg_redirect_hash,
	struct sk_msg_md*, struct bpf_map_def*, void*, __u64)
MAKEFUNC(int, sock_hash_update,
	struct bpf_sock_ops*, struct bpf_map_def*, void*, __u64)
MAKEFUNC(void*, map_lookup_elem, void*, const void*)
MAKEFUNC(int, map_delete_elem, void*, const void*)
MAKEFUNC(__u64, ktime_get_ns, void)
MAKEFUNC(int, map_update_elem, void* map, const void *key, const void *value, __u64 flags)
MAKEFUNC(int, skb_load_bytes, void *ctx, int off, void *to, int len)
MAKEFUNC(__u32, get_prandom_u32)
MAKEFUNC(void, trace_printk, const char *fmt, int fmt_size, ...)
MAKEFUNC(int, redirect, int ifindex, __u32 flags)
MAKEFUNC(int, redirect_map, void *map, __u32 key, __u64 flags)
MAKEFUNC(void, tail_call, void *ctx, void *map, uint32_t index)
MAKEFUNC(void, skb_store_bytes, void *ctx, __u32 offset, const void *from, __u32 len, __u64 flags)
MAKEFUNC(int, l4_csum_replace, void *ctx, __u32 offset, __u64 from, __u64 to, __u64 flags)
MAKEFUNC(void, l3_csum_replace, void *ctx, __u32 offset, __u64 from, __u64 to, __u64 flags)
MAKEFUNC(int, fib_lookup, void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags)

#define printk(fmt, ...) do { char fmt2[] = fmt; bpf_trace_printk(fmt2, sizeof(fmt2) , ## __VA_ARGS__); } while (0)

/*
 * Data types, structs, and unions
 */

struct ip4key {
	__u32 mask;
	__u32 addr;
};

union ip4_bpf_lpm_trie_key {
	struct bpf_lpm_trie_key lpm;
	struct ip4key ip;
};

// helper functions
CALI_BPF_INLINE void ip4val_to_lpm(
	union ip4_bpf_lpm_trie_key *ret, __u32 mask, __u32 addr) {
	ret->lpm.prefixlen = mask;
	ret->ip.addr = addr;
}

CALI_BPF_INLINE __u32 port_to_host(__u32 port) {
	return be32_to_host(port) >> 16;
}

CALI_BPF_INLINE __u32 safe_extract_port(__u32 port) {
	// The verifier doesn't seem to like reading something different than
	// 32 bits for these fields:
	//
	// https://github.com/torvalds/linux/commit/303def35f64e37bcd5401d202889f5fbc0241179#diff-ecd5cf968e9720d49c4360acef3e8e32R5160
	//
	// Trick the optimizer to load the full 32 bits
	// instead of only 16.
	return (port >> 16) | (port & 0xffff);
}

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


enum calico_tc_flags {
	CALI_TC_HOST_EP = 1<<0,
	CALI_TC_INGRESS = 1<<1,
	CALI_TC_TUNNEL  = 1<<2,
};

#define CALI_TC_FLAGS_TO_HOST(flags) (((flags & CALI_TC_HOST_EP) && (flags & CALI_TC_INGRESS)) || \
		(!(flags & CALI_TC_HOST_EP) && !(flags & CALI_TC_INGRESS)))

#define CALI_TC_FLAGS_FROM_WORKLOAD(flags) (!(flags & CALI_TC_HOST_EP) && !(flags & CALI_TC_INGRESS))

#define CALI_TC_FLAGS_L3(flags) ((flags & CALI_TC_HOST_EP) && !(flags & CALI_TC_INGRESS) && (flags & CALI_TC_TUNNEL))

#define CALI_TC_FLAGS_ENCAPPED(flags) ((flags & CALI_TC_INGRESS) && (flags & CALI_TC_TUNNEL))

enum calico_skb_mark {
	// TODO allocate marks from the mark pool.
	CALI_SKB_MARK_SEEN = 0xca110000,
	CALI_SKB_MARK_SEEN_MASK = 0xffff0000,
	CALI_SKB_MARK_NO_TRACK      = 1<<1,
};

#endif /* __CALI_BPF_H__ */
