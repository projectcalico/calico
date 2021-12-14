// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

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
