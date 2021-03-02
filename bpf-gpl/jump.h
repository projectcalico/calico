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

#ifndef __CALI_BPF_JUMP_H__
#define __CALI_BPF_JUMP_H__

#include "conntrack.h"
#include "policy.h"

CALI_MAP(cali_v4_state, 3,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, struct cali_tc_state,
		1, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE struct cali_tc_state *state_get(void)
{
	__u32 key = 0;
	return cali_v4_state_lookup_elem(&key);
}

struct bpf_map_def_extended __attribute__((section("maps"))) cali_jump = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 8,
#ifndef __BPFTOOL_LOADER__
	.map_id = 1,
	.pinning_strategy = 1 /* object namespace */,
#endif
};

static CALI_BPF_INLINE void tc_state_fill_from_iphdr(struct cali_tc_state *state, struct iphdr *ip)
{
	state->ip_src = ip->saddr;
	state->ip_dst = ip->daddr;
	state->ip_proto = ip->protocol;
}

/* Add new values to the end as these are program indices */
enum cali_jump_index {
	PROG_INDEX_POLICY,
	PROG_INDEX_EPILOGUE,
	PROG_INDEX_ICMP,
};
#endif /* __CALI_BPF_JUMP_H__ */
