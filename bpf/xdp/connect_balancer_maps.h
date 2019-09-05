#ifndef __CALICO_CONNECT_BALANCER_MAPS_H__
#define __CALICO_CONNECT_BALANCER_MAPS_H__

#include <bpf/libbpf.h>
#include <stdint.h>

#include "bpf.h"

/* vip_info defines where to find information about the backends of a specific
 * VIP
 */
struct vip_info {
	uint32_t id;
	uint32_t count; /* number of backends */
};

typedef uint32_t ipv4_t;

#define MAX_VIPS    1000000

struct bpf_map_def vip_info_map_v4 __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(ipv4_t),
	.value_size     = sizeof(struct vip_info),
	.max_entries    = MAX_VIPS,
	.map_flags      = BPF_F_NO_PREALLOC,
};

#define MAX_BACKENDS MAX_VIPS

struct backend_key {
	uint32_t vip_id;
	uint32_t order;
};

struct bpf_map_def vip_backends_map_v4 __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct backend_key),
	.value_size     = sizeof(ipv4_t),
	.max_entries    = MAX_BACKENDS,
	.map_flags      = BPF_F_NO_PREALLOC,
};

#endif /* __CALICO_CONNECT_BALANCER_MAPS_H__ */
