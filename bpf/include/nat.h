#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#include <linux/in.h>
#import "bpf.h"

// Map: NAT level one.  Dest IP and port -> ID and num backends.

struct calico_nat_v4_key {
	uint32_t addr; // NBO
	uint16_t port; // HBO
	uint8_t protocol;
	uint8_t pad;
};

struct calico_nat_v4_value {
	uint32_t id;
	uint32_t count;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_nat_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_nat_v4_key),
	.value_size = sizeof(struct calico_nat_v4_value),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 511000, // arbitrary
	.pinning_strategy = 2 /* global namespace */,
};

// Map: NAT level two.  ID and ordinal -> new dest and port.

struct calico_nat_secondary_v4_key {
	uint32_t id;
	uint32_t ordinal;
};

struct calico_nat_dest {
	uint32_t addr;
	uint16_t port;
	uint8_t pad[2];
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_natbe_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_nat_secondary_v4_key),
	.value_size = sizeof(struct calico_nat_dest),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 510000, // arbitrary
	.pinning_strategy = 2 /* global namespace */,
};

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup(__u8 ip_proto, __be32 ip_dst, __u16 dport,
	enum calico_tc_flags flags) {
	if (((flags & CALI_TC_HOST_EP) && !(flags & CALI_TC_INGRESS)) ||
		(!(flags & CALI_TC_HOST_EP) && (flags & CALI_TC_INGRESS))) {
		// Skip NAT lookup for traffic leaving the host namespace.
		return NULL;
	}

	struct calico_nat_v4_key nat_key = {
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
	};

	struct calico_nat_v4_value *nat_lv1_val = bpf_map_lookup_elem(&cali_nat_v4, &nat_key);
	CALI_DEBUG("NAT: 1st level lookup addr=%x port=%d protocol=%d.\n",
		(int)be32_to_host(nat_key.addr), (int)dport,
		(int)(nat_key.protocol));
	if (!nat_lv1_val) {
		CALI_DEBUG("NAT: Miss.\n");
		return NULL;
	}

	struct calico_nat_secondary_v4_key nat_lv2_key = {
		.id = nat_lv1_val->id,
		.ordinal = bpf_get_prandom_u32() % nat_lv1_val->count,
	};
	CALI_DEBUG("NAT: 1st level hit; id=%d ordinal=%d\n", nat_lv2_key.id, nat_lv2_key.ordinal);
	struct calico_nat_dest *nat_lv2_val = bpf_map_lookup_elem(&cali_natbe_v4,
		&nat_lv2_key);
	if (nat_lv2_val) {
		CALI_DEBUG("NAT: backend selected %x:%d\n", be32_to_host(nat_lv2_val->addr), nat_lv2_val->port);
	} else {
		CALI_DEBUG("NAT: backend miss\n");
	}
	return nat_lv2_val;
}

#endif /* __CALI_NAT_H__ */
