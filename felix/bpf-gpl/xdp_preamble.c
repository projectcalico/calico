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

const volatile struct cali_xdp_globals __globals;

SEC("xdp")
int  cali_xdp_preamble(struct __sk_buff *skb)
{
	struct cali_xdp_globals *globals = state_get_globals_xdp();

	if (!globals) {
		return TC_ACT_SHOT;
	}

	/* Set the globals for the rest of the prog chain. */
	*globals = __globals;

#if EMIT_LOGS
	CALI_LOG("xdp_preamble iface %s\n", globals->iface_name);
#endif

	/* Jump to the start of the prog chain. */
	bpf_tail_call(skb, &cali_jump_map, globals->jumps[PROG_INDEX_MAIN]);
	CALI_LOG("xdp_preamble iface %s failed to call main %d\n", globals->iface_name, globals->jumps[PROG_INDEX_MAIN]);
	/* Drop the packet in the unexpected case of not being able to make the jump. */
	return TC_ACT_SHOT;
}
