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
#include <stddef.h>
#include <linux/ip.h>

/* Kernel/libbpf bpf_helpers.h also contain this struct 'bpf_map_def' */
struct bpf_map_def {
        unsigned int type;
        unsigned int key_size;
        unsigned int value_size;
        unsigned int max_entries;
        unsigned int map_flags;
};

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

#endif /* __CALI_BPF_H__ */
