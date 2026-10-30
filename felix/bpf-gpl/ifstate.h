// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_IFSTATE_H__
#define __CALI_IFSTATE_H__

#include "cali_bpf.h"

struct ifstate_val {
	__u32 flags;
	char  name[16];
	__s32 xdp_policy_v4;
	__s32 ingress_policy_v4;
	__s32 egress_policy_v4;
	__s32 xdp_policy_v6;
	__s32 ingress_policy_v6;
	__s32 egress_policy_v6;
	__s32 tc_filter_ingress;
	__s32 tc_filter_egress;
};

#define IFACE_STATE_MAP_SIZE 1000

CALI_MAP(cali_iface, 4,
		BPF_MAP_TYPE_HASH,
		__u32, struct ifstate_val,
		IFACE_STATE_MAP_SIZE, BPF_F_NO_PREALLOC)

#define IFACE_STATE_WEP         0x1
#define IFACE_STATE_V4_READY    0x2
#define IFACE_STATE_V6_READY    0x4
#define IFACE_STATE_HEP         0x8
#define IFACE_STATE_VXLAN       0x40
#define IFACE_STATE_IPIP        0x80
#define IFACE_STATE_WIREGUARD   0x100
#define IFACE_STATE_NOT_MANAGED 0x400

#define iface_is_workload(state)		((state) & IFACE_STATE_WEP)
#define iface_is_not_managed(state)		((state) & IFACE_STATE_NOT_MANAGED)
/* The device adds its own header, so a packet may leave it as an inner frame. */
#define iface_encaps(state)			((state) & (IFACE_STATE_VXLAN | \
							    IFACE_STATE_IPIP | \
							    IFACE_STATE_WIREGUARD))
#ifdef IPVER6
#define iface_is_ready(state)	((state) & IFACE_STATE_V6_READY)
#else
#define iface_is_ready(state)	((state) & IFACE_STATE_V4_READY)
#endif

static CALI_BPF_INLINE bool iface_can_encap(__u32 ifindex)
{
	struct ifstate_val *val = cali_iface_lookup_elem(&ifindex);

	return val && iface_encaps(val->flags);
}

#endif /* __CALI_IFSTATE_H__ */
