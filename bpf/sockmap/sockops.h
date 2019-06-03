#include "../include/bpf.h"

#define ENVOY_IP 0x100007f
#define ENVOY_PORT 0x993a

struct sock_key {
	__u32 ip4;
	__u32 port;
	__u32 envoy_side;
};

struct bpf_elf_map __section(ELF_SECTION_MAPS) calico_sock_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.size_key       = sizeof(struct sock_key),
	.size_value     = sizeof(int),
	.max_elem       = 65535,
};
