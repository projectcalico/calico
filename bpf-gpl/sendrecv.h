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

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_srmsg = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct sendrecv4_key),
	.value_size = sizeof(struct sendrecv4_val),
	.max_entries = 510000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE uint16_t ctx_port_to_host(__u32 port)
{
	return be32_to_host(port) >> 16;
}

static CALI_BPF_INLINE __u32 host_to_ctx_port(uint16_t port)
{
	return host_to_be32(((uint32_t)port) << 16);
}

#endif /* __SENDRECV_H__ */
