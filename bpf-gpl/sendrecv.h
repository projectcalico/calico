// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __SENDRECV_H__
#define __SENDRECV_H__

struct sendrecv4_key {
	__u64 cookie;
	__u32 ip;
	__u32 port; /* because bpf_sock_addr uses 32bit and we would need padding */
};

struct sendrecv4_val {
	__u32 ip;
	__u32 port; /* because bpf_sock_addr uses 32bit and we would need padding */
};

CALI_MAP_V1(cali_v4_srmsg,
		BPF_MAP_TYPE_LRU_HASH,
		struct sendrecv4_key, struct sendrecv4_val,
		510000, 0, MAP_PIN_GLOBAL)

struct ct_nats_key {
	__u64 cookie;
	__u32 ip;
	__u32 port; /* because bpf_sock_addr uses 32bit */
	__u8 proto;
	__u8 pad[7];
};

CALI_MAP_V1(cali_v4_ct_nats,
		BPF_MAP_TYPE_LRU_HASH,
		struct ct_nats_key, struct sendrecv4_val,
		10000, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE __u16 ctx_port_to_host(__u32 port)
{
	return bpf_ntohl(port) >> 16;
}

static CALI_BPF_INLINE __u32 host_to_ctx_port(__u16 port)
{
	return bpf_htonl(((__u32)port) << 16);
}

#endif /* __SENDRECV_H__ */
