// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ARP_H__
#define __CALI_ARP_H__

struct arp_key {
	__u32 ip;
	__u32 ifindex;
};

struct arp_value {
	char mac_src[6];
	char mac_dst[6];
};

CALI_MAP(cali_v4_arp, 2, BPF_MAP_TYPE_LRU_HASH, struct arp_key, struct arp_value, 10000, 0, MAP_PIN_GLOBAL)

#endif /* __CALI_ARP_H__ */
