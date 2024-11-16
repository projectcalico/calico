// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>
#include <linux/if_ether.h>

#include "skb.h"
#include "bpf.h"
#include "types.h"
#include "globals.h"
#include "jump.h"
#include "log.h"

const volatile struct cali_xdp_preamble_globals __globals;

static CALI_BPF_INLINE __u16 parse_eth_hdr(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = (void *)(long)xdp->data;
	__u64 offset = sizeof(*eth);
	if ((void *)eth + offset > data_end) {
		bpf_exit(XDP_DROP);
	}
	return bpf_ntohs(eth->h_proto);
}

SEC("xdp")
int  cali_xdp_preamble(struct xdp_md *xdp)
{
	struct cali_xdp_globals *globals = state_get_globals_xdp();

	if (!globals) {
		return XDP_DROP;
	}
	__u16 protocol = parse_eth_hdr(xdp);
	if (protocol == 0xffff) {
		return XDP_DROP;
	}

	if (protocol == ETH_P_IPV6 && (__globals.v6.jumps[PROG_INDEX_MAIN] != (__u32)-1)) {
		*globals = __globals.v6;
	} else if (protocol == ETH_P_IP && (__globals.v4.jumps[PROG_INDEX_MAIN] != (__u32)-1)) {
		*globals = __globals.v4;
	} else {
		return XDP_PASS;
	}

#if EMIT_LOGS
	CALI_LOG("xdp_preamble iface %s", globals->iface_name);
#endif

	/* Jump to the start of the prog chain. */
	bpf_tail_call(xdp, &cali_jump_map, ((volatile __u32*)(globals->jumps))[PROG_INDEX_MAIN]);
	CALI_LOG("xdp_preamble iface %s failed to call main %d", globals->iface_name, globals->jumps[PROG_INDEX_MAIN]);
	/* Drop the packet in the unexpected case of not being able to make the jump. */
	return XDP_DROP;
}
