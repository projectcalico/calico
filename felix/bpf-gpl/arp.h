// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ARP_H__
#define __CALI_ARP_H__

#include "ip_addr.h"

struct arp_key {
	ipv46_addr_t ip;
	__u32 ifindex;
};

struct arp_value {
	char mac_src[6];
	char mac_dst[6];
};

#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_arp, cali_arp, 2, BPF_MAP_TYPE_LRU_HASH, struct arp_key, struct arp_value, 10000, 0)
#else
CALI_MAP_NAMED(cali_v4_arp, cali_arp, 2, BPF_MAP_TYPE_LRU_HASH, struct arp_key, struct arp_value, 10000, 0)
#endif

#endif /* __CALI_ARP_H__ */
