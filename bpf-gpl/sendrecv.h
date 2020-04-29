// Copyright (c) 2020 Tigera, Inc. All rights reserved.

#ifndef __SENDRECV_H__
#define __SENDRECV_H__

struct sendrecv4_key {
	uint64_t cookie;
	uint32_t ip;
	uint32_t port; /* because bpf_sock_addr uses 32bit and we would need padding */
};

struct sendrecv4_val {
	uint32_t ip;
	uint32_t port; /* because bpf_sock_addr uses 32bit and we would need padding */
};

CALI_MAP_V1(cali_v4_srmsg,
		BPF_MAP_TYPE_LRU_HASH,
		struct sendrecv4_key, struct sendrecv4_val,
		510000, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE uint16_t ctx_port_to_host(__u32 port)
{
	return be32_to_host(port) >> 16;
}

static CALI_BPF_INLINE __u32 host_to_ctx_port(uint16_t port)
{
	return host_to_be32(((uint32_t)port) << 16);
}

#endif /* __SENDRECV_H__ */
