// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

#ifndef __CALI_BPF_FAILSAFE_H__
#define __CALI_BPF_FAILSAFE_H__

#include "bpf.h"
#include "types.h"

struct failsafe_key {
	__u32 prefixlen;
	__u16 port;
	__u8 ip_proto;
	__u8 flags;
	__u32 addr;
};

struct failsafe_val {
	__u32 unused;
};

CALI_MAP(cali_v4_fsafes, 2,
		BPF_MAP_TYPE_LPM_TRIE,
		struct failsafe_key, struct failsafe_val,
		65536,
		BPF_F_NO_PREALLOC,
		MAP_PIN_GLOBAL)

#define CALI_FSAFE_OUT 1


/* Prefix len = (port + protocol + addr) in bits. */
#define FSAFE_PREFIX_LEN  (sizeof(struct failsafe_key) - \
				sizeof(((struct failsafe_key*)0)->prefixlen))

#define FSAFE_PREFIX_LEN_IN_BITS (FSAFE_PREFIX_LEN * 8)

static CALI_BPF_INLINE bool is_failsafe_in(__u8 ip_proto, __u16 dport, __be32 ip) {
	struct failsafe_key key = {
		.prefixlen = FSAFE_PREFIX_LEN_IN_BITS,
		.ip_proto = ip_proto,
		.port = dport,
		.flags = 0,
		.addr = ip,
	};
	if (cali_v4_fsafes_lookup_elem(&key)) {
		return true;
	}
	return false;
}

static CALI_BPF_INLINE bool is_failsafe_out(__u8 ip_proto, __u16 dport, __be32 ip) {
	struct failsafe_key key = {
		.prefixlen = FSAFE_PREFIX_LEN_IN_BITS,
		.ip_proto = ip_proto,
		.port = dport,
		.flags = CALI_FSAFE_OUT,
		.addr = ip,
	};
	if (cali_v4_fsafes_lookup_elem(&key)) {
		return true;
	}
	return false;
}

#endif /* __CALI_BPF_FAILSAFE_H__ */
