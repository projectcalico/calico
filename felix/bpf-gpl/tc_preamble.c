// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>
#include <linux/if_ether.h>

#include "bpf.h"
#include "types.h"
#include "globals.h"
#include "jump.h"
#include "log.h"

const volatile struct cali_tc_preamble_globals __globals;

#define JUMP_IDX(idx) (idx)
#define JUMP_IDX_DEBUG(idx) (idx ## _DEBUG)

#define JUMP(idx) globals->data.jumps[JUMP_IDX(idx)]
#define JUMP_DEBUG(idx) globals->data.jumps[JUMP_IDX_DEBUG(idx)]

SEC("tc")
int  cali_tc_preamble(struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();
	const volatile struct cali_tc_global_data *globals_data = NULL;

	if (!globals) {
		return TC_ACT_SHOT;
	}

	__u16 protocol = bpf_ntohs(skb->protocol);
	/* Set the globals for the rest of the prog chain. */
	if (protocol == ETH_P_IPV6) {
		if (__globals.v6.jumps[PROG_INDEX_MAIN] != (__u32)-1) {
			globals_data = &__globals.v6;
		} else if (__globals.v4.jumps[PROG_INDEX_MAIN] != (__u32)-1) {
			globals_data = &__globals.v4;
		}
	} else {
		if (__globals.v4.jumps[PROG_INDEX_MAIN] != (__u32)-1) {
			globals_data = &__globals.v4;
		} else if (__globals.v6.jumps[PROG_INDEX_MAIN] != (__u32)-1) {
			globals_data = &__globals.v6;
		}
	}

	if (!globals_data) {
		CALI_LOG("Main program not loaded for IP packet version %d, DROP", protocol);
		return TC_ACT_SHOT;
	}

	/* We do the copy once here so keep the program smaller */
	globals->data = *globals_data;

#if EMIT_LOGS
	CALI_LOG("tc_preamble iface %s", globals->data.iface_name);
#endif

	/* If we have log filter installed, tell the filter where to jump next
	 * and jump to the filter.
	 */
	if (globals->data.log_filter_jmp != (__u32)-1) {
		skb->cb[0] = JUMP(PROG_INDEX_MAIN);
		skb->cb[1] = JUMP_DEBUG(PROG_INDEX_MAIN);
		bpf_tail_call(skb, &cali_jump_prog_map, globals->data.log_filter_jmp);
		CALI_LOG("tc_preamble iface %s failed to call log filter %d",
				globals->data.iface_name, globals->data.log_filter_jmp);
		/* try to jump to the regular path */
	}

	/* Jump to the start of the prog chain. */
#if EMIT_LOGS
	CALI_LOG("tc_preamble iface %s jump to %d",
			globals->data.iface_name, JUMP(PROG_INDEX_MAIN));
#endif
	bpf_tail_call(skb, &cali_jump_map, JUMP(PROG_INDEX_MAIN));
	CALI_LOG("tc_preamble iface %s failed to call main %d",
			globals->data.iface_name, JUMP(PROG_INDEX_MAIN));

	/* Try debug path in the unexpected case of not being able to make the jump. */
	CALI_LOG("tc_preamble iface %s jump to %d",
			globals->data.iface_name, JUMP_DEBUG(PROG_INDEX_MAIN));
	bpf_tail_call(skb, &cali_jump_map, JUMP_DEBUG(PROG_INDEX_MAIN));
	CALI_LOG("tc_preamble iface %s failed to call debug main %d",
			globals->data.iface_name, JUMP_DEBUG(PROG_INDEX_MAIN));

	/* Drop the packet in the unexpected case of not being able to make the jump. */
	CALI_LOG("tc_preamble iface %s failed to call main %d", globals->data.iface_name, JUMP(PROG_INDEX_MAIN));

	return TC_ACT_SHOT;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-local-typedef"
#pragma clang diagnostic ignored "-Wunused"
static CALI_BPF_INLINE void __compile_tc_asserts(void) {
/* We store globals in the state map to pass them between programs, they must fit! */
COMPILE_TIME_ASSERT(sizeof(struct cali_tc_globals) < sizeof(struct cali_tc_state))
}
#pragma clang diagnostic pop
