// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NODEPORT_TUN_H__
#define __CALI_NODEPORT_TUN_H__

#include "cali_bpf.h"
#include "ip_addr.h"
#include "log.h"
#include "types.h"

/* Outer addresses for the VXLAN tunnel that carries nodeport traffic to a
 * backend on another node.
 */

/* np_tun_src sets *src to the tunnel's outer source.  Returns false, leaving
 * *src untouched, if this node has no address to use.
 */
static CALI_BPF_INLINE bool np_tun_src(struct cali_tc_ctx *ctx, ipv46_addr_t *src)
{
	if (ip_void(HOST_IP)) {
		CALI_DEBUG("VXLAN encap needed but host IP unknown; dropping");
		return false;
	}
	*src = HOST_IP;
	return true;
}

/* np_tun_dst sets *dst to the tunnel's outer destination for the node whose
 * primary IP is *node_ip.  Returns false, leaving *dst untouched, if that node
 * is unreachable.  Called for new flows only; conntrack keeps *dst as tun_ip.
 */
static CALI_BPF_INLINE bool np_tun_dst(struct cali_tc_ctx *ctx, const ipv46_addr_t *node_ip,
				       ipv46_addr_t *dst)
{
	*dst = *node_ip;
	return true;
}

#endif /* __CALI_NODEPORT_TUN_H__ */
