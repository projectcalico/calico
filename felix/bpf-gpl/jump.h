// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_JUMP_H__
#define __CALI_BPF_JUMP_H__

CALI_MAP(cali_state, 3,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, struct cali_tc_state,
		2, 0)

static CALI_BPF_INLINE struct cali_tc_state *state_get(void)
{
	__u32 key = 0;
	return cali_state_lookup_elem(&key);
}

/* N.B. we just grab large enough chunk of data in the state map. State is so
 * large that the globals fit in the extra slot in the array. The get functions
 * just typecast it to the desired type of globals.
 */

static CALI_BPF_INLINE struct cali_tc_globals *state_get_globals_tc(void)
{
	__u32 key = 1;
	return cali_state_lookup_elem(&key);
}

static CALI_BPF_INLINE struct cali_xdp_globals *state_get_globals_xdp(void)
{
	__u32 key = 1;
	return cali_state_lookup_elem(&key);
}

#if CALI_F_XDP

#define cali_jump_map map_symbol(xdp_cali_progs, 2)

struct bpf_map_def_extended __attribute__((section("maps"))) cali_jump_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 200,
};

#define CALI_JUMP_TO(ctx, index) bpf_tail_call((ctx)->xdp, &cali_jump_map, (ctx)->xdp_globals->jumps[index])
#else

#define cali_jump_map map_symbol(cali_progs, 2)

struct bpf_map_def_extended __attribute__((section("maps"))) cali_jump_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 200,
};

#define CALI_JUMP_TO(ctx, index) do {	\
	CALI_DEBUG("jump to idx %d prog at %d\n", index, (ctx)->globals->jumps[index]);	\
	bpf_tail_call((ctx)->skb, &cali_jump_map, (ctx)->globals->jumps[index]);	\
} while (0)
#endif

/* Add new values to the end as these are program indices */
enum cali_jump_index {
	PROG_INDEX_MAIN,
	PROG_INDEX_POLICY,
	PROG_INDEX_ALLOWED,
	PROG_INDEX_ICMP,
	PROG_INDEX_DROP,
	PROG_INDEX_HOST_CT_CONFLICT,
	PROG_INDEX_V6_PROLOGUE,
	PROG_INDEX_V6_POLICY,
	PROG_INDEX_V6_ALLOWED,
	PROG_INDEX_V6_ICMP,
	PROG_INDEX_V6_DROP,
};

#if CALI_F_XDP

#define cali_policy_map map_symbol(xdp_cali_pols, 2)

struct bpf_map_def_extended __attribute__((section("maps"))) cali_policy_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 100,
};

#define CALI_JUMP_TO_POLICY(ctx) bpf_tail_call((ctx)->xdp, &cali_policy_map, (ctx)->xdp_globals->jumps[PROG_INDEX_POLICY])

#else

#define cali_policy_map map_symbol(cali_pols, 2)

struct bpf_map_def_extended __attribute__((section("maps"))) cali_policy_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 10000,
};

#define CALI_JUMP_TO_POLICY(ctx) do {	\
	(ctx)->skb->cb[0] = (ctx)->globals->jumps[PROG_INDEX_ALLOWED];				\
	(ctx)->skb->cb[1] = (ctx)->globals->jumps[PROG_INDEX_DROP];				\
	CALI_DEBUG("jump to policy prog at %d\n", (ctx)->globals->jumps[PROG_INDEX_POLICY]);	\
	bpf_tail_call((ctx)->skb, &cali_policy_map, (ctx)->globals->jumps[PROG_INDEX_POLICY]);	\
} while (0)

#endif

#endif /* __CALI_BPF_JUMP_H__ */
