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

// struct cali_tc_state holds state that is passed between the BPF programs.
// WARNING: must be kept in sync with the definitions in bpf/polprog/pol_prog_builder.go.
struct cali_tc_state {
	__be32 ip_src;
	__be32 ip_dst;
	__be32 post_nat_ip_dst;
	__be32 nat_tun_src;
	__s32 pol_rc;
	__u16 sport;
	__u16 dport;
	__u16 post_nat_dport;
	__u8 ip_proto;
	__u8 flags;
	struct calico_ct_result ct_result;
	struct calico_nat_dest nat_dest;
	__u64 prog_start_time;
};

enum cali_state_flags {
	CALI_ST_NAT_OUTGOING = 1,
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_state = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(uint32_t),
	.value_size     = sizeof(struct cali_tc_state),
	.max_entries    = 1,
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

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

#endif /* __CALI_BPF_JUMP_H__ */
