// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __CALI_ARP_H__
#define __CALI_ARP_H__

struct arp_key {
	uint32_t ip;
	uint32_t ifindex;
};

struct arp_value {
	char mac_src[6];
	char mac_dst[6];
};

CALI_MAP(cali_v4_arp, 2, BPF_MAP_TYPE_LRU_HASH, struct arp_key, struct arp_value, 10000, 0, MAP_PIN_GLOBAL)

#endif /* __CALI_ARP_H__ */
