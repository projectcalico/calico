// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "globals.h"
#include "jump.h"
#include "log.h"

const volatile struct cali_tc_globals __globals;

SEC("classifier/tc/preamble")
int  cali_tc_preamble(struct __sk_buff *skb)
{
	volatile struct cali_tc_globals *globals = state_get_globals_tc();

	if (!globals) {
		return TC_ACT_SHOT;
	}

	/* Set the globals for the rest of the prog chain. */
	*globals = __globals;

#if EMIT_LOGS
	CALI_LOG("tc_preamble iface %s\n", globals->iface_name);
#endif

	/* If we have log filter installed, tell the filter where to jump next
	 * and jump to the filter.
	 */
	if (globals->log_filter_jmp != (__u32)-1) {
		skb->cb[0] = globals->jumps[PROG_INDEX_MAIN];
		skb->cb[1] = globals->jumps[PROG_INDEX_MAIN_DEBUG];
		bpf_tail_call(skb, &cali_jump_prog_map, globals->log_filter_jmp);
		CALI_LOG("tc_preamble iface %s failed to call log filter %d\n",
				globals->iface_name, globals->log_filter_jmp);
		/* try to jump to the regular path */
	}

	/* Jump to the start of the prog chain. */
#if EMIT_LOGS
	CALI_LOG("tc_preamble iface %s jump to %d\n",
			globals->iface_name, globals->jumps[PROG_INDEX_MAIN]);
#endif
	bpf_tail_call(skb, &cali_jump_map, globals->jumps[PROG_INDEX_MAIN]);
	CALI_LOG("tc_preamble iface %s failed to call main %d\n",
			globals->iface_name, globals->jumps[PROG_INDEX_MAIN]);

	/* Try debug path in the unexpected case of not being able to make the jump. */
	CALI_LOG("tc_preamble iface %s jump to %d\n",
			globals->iface_name, globals->jumps[PROG_INDEX_MAIN_DEBUG]);
	bpf_tail_call(skb, &cali_jump_map, globals->jumps[PROG_INDEX_MAIN_DEBUG]);
	CALI_LOG("tc_preamble iface %s failed to call debug main %d\n",
			globals->iface_name, globals->jumps[PROG_INDEX_MAIN_DEBUG]);

	/* Drop the packet in the unexpected case of not being able to make the jump. */
	CALI_LOG("tc_preamble iface %s failed to call main %d\n", globals->iface_name, globals->jumps[PROG_INDEX_MAIN]);

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
