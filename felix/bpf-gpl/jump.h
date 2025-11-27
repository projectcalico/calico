// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_JUMP_H__
#define __CALI_BPF_JUMP_H__

#include "types.h"

CALI_MAP(cali_state, 4,
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

#define cali_jump_map map_symbol(xdp_cali_progs, 3)

CALI_MAP_V1(cali_jump_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 400, 0)

#define CALI_JUMP_TO(ctx, index) bpf_tail_call((ctx)->xdp, &cali_jump_map, (ctx)->xdp_globals->jumps[PROG_PATH(index)])

#else /* CALI_F_XDP */

/*
 * BPF programs have a type, which depends on where they are attached. 
 * As of kernel 6.12, jump maps are limited to a single program type and 
 * it is forbidden to jump from one type of program to a different type of map.
 * TCX ingress and egress programs have different types, so this means that we need to split the jump maps for the two directions.
 * Note: in our code, we generally use "ingress" and "egress" to refer to the policy direction, 
 * relative to the endpoint that is being secured, which means that, for workload endpoints, 
 * "ingress" policy is implemented in the kernel's "egress" tc(x) program(!). 
 * To avoid (further) confusion, we call the kernel's directions "to host" (ingress) and "from host" (egress).
*/

#if CALI_F_HEP || CALI_F_PREAMBLE
#if CALI_F_INGRESS
#define cali_jump_map map_symbol(cali_progs_fh, 2)
#else
#define cali_jump_map map_symbol(cali_progs_th, 2)
#endif
#else
#if CALI_F_INGRESS
#define cali_jump_map map_symbol(cali_progs_th, 2)
#else
#define cali_jump_map map_symbol(cali_progs_fh, 2)
#endif
#endif
CALI_MAP_V1(cali_jump_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 400, 0)

#define __CALI_JUMP_TO(ctx, index) do {	\
	CALI_DEBUG("jump to idx %d prog at %d", index, (ctx)->globals->data.jumps[PROG_PATH(index)]);	\
	bpf_tail_call((ctx)->skb, &cali_jump_map, (ctx)->globals->data.jumps[PROG_PATH(index)]);	\
} while (0)

#define CALI_JUMP_TO(ctx, index) __CALI_JUMP_TO(ctx, index)

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
	PROG_INDEX_NEW_FLOW,
	PROG_INDEX_IP_FRAG,
	PROG_INDEX_MAGLEV,

	PROG_INDEX_MAIN_DEBUG,
	PROG_INDEX_POLICY_DEBUG,
	PROG_INDEX_ALLOWED_DEBUG,
	PROG_INDEX_ICMP_DEBUG,
	PROG_INDEX_DROP_DEBUG,
	PROG_INDEX_HOST_CT_CONFLICT_DEBUG,
	PROG_INDEX_ICMP_INNER_NAT_DEBUG,
	PROG_INDEX_NEW_FLOW_DEBUG,
	PROG_INDEX_IP_FRAG_DEBUG,
	PROG_INDEX_MAGLEV_DEBUG,
};

#if CALI_F_XDP

#define cali_jump_prog_map map_symbol(xdp_cali_jump, 3)

CALI_MAP_V1(cali_jump_prog_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 2400, 0)

/* We on any path, we always jump to the PROG_INDEX_POLICY for policy, that one
 * is shared!
 */
#define CALI_JUMP_TO_POLICY(ctx) \
	bpf_tail_call((ctx)->xdp, &cali_jump_prog_map, (ctx)->xdp_globals->jumps[PROG_INDEX_POLICY])
#else /* CALI_F_XDP */

#define cali_jump_prog_map map_symbol(cali_jump, 3)

CALI_MAP_V1(cali_jump_prog_map, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, 240000, 0)

#define __CALI_JUMP_TO_POLICY(ctx, allow, deny, pol) do {	\
	(ctx)->skb->cb[0] = (ctx)->globals->data.jumps[PROG_PATH(allow)];			\
	(ctx)->skb->cb[1] = (ctx)->globals->data.jumps[PROG_PATH(deny)];				\
	CALI_DEBUG("policy allow prog at %d", (ctx)->globals->data.jumps[PROG_PATH(allow)]);	\
	CALI_DEBUG("policy deny prog at %d", (ctx)->globals->data.jumps[PROG_PATH(deny)]);	\
	CALI_DEBUG("jump to policy prog at %d", (ctx)->globals->data.jumps[pol]);		\
	bpf_tail_call((ctx)->skb, &cali_jump_prog_map, (ctx)->globals->data.jumps[pol]);	\
} while (0)

#define CALI_JUMP_TO_POLICY(ctx) \
	__CALI_JUMP_TO_POLICY(ctx, PROG_INDEX_ALLOWED, PROG_INDEX_DROP, PROG_INDEX_POLICY)
#endif

#endif /* __CALI_BPF_JUMP_H__ */
