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

#define PROG_PATH(idx) ((CALI_LOG_LEVEL < CALI_LOG_LEVEL_DEBUG) ? idx : idx ## _DEBUG)

#if CALI_F_XDP

#define cali_jump_map map_symbol(xdp_cali_progs, 2)

CALI_MAP_V1(cali_jump_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 200, 0)

#define CALI_JUMP_TO(ctx, index) bpf_tail_call((ctx)->xdp, &cali_jump_map, (ctx)->xdp_globals->jumps[PROG_PATH(index)])
#else

#define cali_jump_map map_symbol(cali_progs, 2)

CALI_MAP_V1(cali_jump_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 200, 0)

#define CALI_JUMP_TO(ctx, index) do {	\
	CALI_DEBUG("jump to idx %d prog at %d\n", index, (ctx)->globals->jumps[PROG_PATH(index)]);	\
	bpf_tail_call((ctx)->skb, &cali_jump_map, (ctx)->globals->jumps[PROG_PATH(index)]);	\
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
	PROG_INDEX_ICMP_INNER_NAT,

	PROG_INDEX_MAIN_DEBUG,
	PROG_INDEX_POLICY_DEBUG,
	PROG_INDEX_ALLOWED_DEBUG,
	PROG_INDEX_ICMP_DEBUG,
	PROG_INDEX_DROP_DEBUG,
	PROG_INDEX_HOST_CT_CONFLICT_DEBUG,
	PROG_INDEX_ICMP_INNER_NAT_DEBUG,

	PROG_INDEX_V6_PROLOGUE,
	PROG_INDEX_V6_POLICY,
	PROG_INDEX_V6_ALLOWED,
	PROG_INDEX_V6_ICMP,
	PROG_INDEX_V6_DROP,

	PROG_INDEX_V6_PROLOGUE_DEBUG,
	PROG_INDEX_V6_POLICY_DEBUG,
	PROG_INDEX_V6_ALLOWED_DEBUG,
	PROG_INDEX_V6_ICMP_DEBUG,
	PROG_INDEX_V6_DROP_DEBUG,
};

#if CALI_F_XDP

#define cali_jump_prog_map map_symbol(xdp_cali_jump, 2)

CALI_MAP_V1(cali_jump_prog_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 100, 0)

/* We on any path, we always jump to the PROG_INDEX_POLICY for policy, that one
 * is shared!
 */
#define CALI_JUMP_TO_POLICY(ctx) \
	bpf_tail_call((ctx)->xdp, &cali_jump_prog_map, (ctx)->xdp_globals->jumps[PROG_INDEX_POLICY])
#else

#define cali_jump_prog_map map_symbol(cali_jump, 2)

CALI_MAP_V1(cali_jump_prog_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 10000, 0)

#define CALI_JUMP_TO_POLICY(ctx) do {	\
	(ctx)->skb->cb[0] = (ctx)->globals->jumps[PROG_PATH(PROG_INDEX_ALLOWED)];			\
	(ctx)->skb->cb[1] = (ctx)->globals->jumps[PROG_PATH(PROG_INDEX_DROP)];				\
	CALI_DEBUG("policy allow prog at %d\n", (ctx)->globals->jumps[PROG_PATH(PROG_INDEX_ALLOWED)]);	\
	CALI_DEBUG("policy deny prog at %d\n", (ctx)->globals->jumps[PROG_PATH(PROG_INDEX_DROP)]);	\
	CALI_DEBUG("jump to policy prog at %d\n", (ctx)->globals->jumps[PROG_INDEX_POLICY]);		\
	bpf_tail_call((ctx)->skb, &cali_jump_prog_map, (ctx)->globals->jumps[PROG_INDEX_POLICY]);	\
} while (0)

#endif

#endif /* __CALI_BPF_JUMP_H__ */
