// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CONNECT_H__
#define __CONNECT_H__

#include <linux/bpf.h>

#include "bpf.h"
#include "nat_lookup.h"

static CALI_BPF_INLINE int do_nat_common(struct bpf_sock_addr *ctx, __u8 proto, ipv46_addr_t *dst, bool connect)
{
	int err = 0;
	/* We do not know what the source address is yet, we only know that it
	 * is the localhost, so we might just use 0.0.0.0. That would not
	 * conflict with traffic from elsewhere.
	 *
	 * XXX it means that all workloads that use the cgroup hook have the
	 * XXX same affinity, which (a) is sub-optimal and (b) leaks info between
	 * XXX workloads.
	 */
	nat_lookup_result res = NAT_LOOKUP_ALLOW;
	__u16 dport_he = (__u16)(bpf_ntohl(ctx->user_port)>>16);
	struct calico_nat_dest *nat_dest;
	ipv46_addr_t voidip = VOID_IP;
	nat_dest = calico_nat_lookup(&voidip, dst, proto, dport_he, false, &res,
			proto == IPPROTO_UDP && !connect ? CTLB_UDP_NOT_SEEN_TIMEO : 0, /* enforce affinity UDP */
			proto == IPPROTO_UDP && !connect /* update affinity timer */);
	if (!nat_dest) {
		CALI_INFO("NAT miss.");
		if (res == NAT_NO_BACKEND) {
			err = -1;
		}
		goto out;
	}

	__be32 dport_be = host_to_ctx_port(nat_dest->port);

	__u64 cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Store: ip=%x port=%d cookie=%x",
			debug_ip(nat_dest->addr), bpf_ntohs((__u16)dport_be), cookie);

	/* For all protocols, record recent NAT operations in an LRU map; other BPF programs use this
	 * cache to reverse our DNAT so they can do pre-DNAT policy. */
	struct ct_nats_key natk = {
		.cookie = cookie,
		.ip = nat_dest->addr,
		.port = dport_be,
		.proto = proto,
	};
	struct sendrec_val val = {
		.ip	= *dst,
		.port	= ctx->user_port,
	};
	int rc = cali_ct_nats_update_elem(&natk, &val, 0);
	if (rc) {
		/* if this happens things are really bad! report */
		CALI_INFO("Failed to update ct_nats map rc=%d", rc);
	}

	if (proto != IPPROTO_TCP) {
		/* For UDP, store a long-lived reverse mapping, which we use to reverse the DNAT for programs that
		 * check the source on the return packets. */
		__u64 cookie = bpf_get_socket_cookie(ctx);
		CALI_DEBUG("Store: ip=%x port=%d cookie=%x",
				debug_ip(nat_dest->addr), bpf_ntohs((__u16)dport_be), cookie);
		struct sendrec_key key = {
			.ip	= nat_dest->addr,
			.port	= dport_be,
			.cookie	= cookie,
		};

		if (cali_srmsg_update_elem(&key, &val, 0)) {
			/* if this happens things are really bad! report */
			CALI_INFO("Failed to update map");
			goto out;
		}
	}

	*dst = nat_dest->addr;
	ctx->user_port = dport_be;

out:
	return err;
}

static CALI_BPF_INLINE int connect(struct bpf_sock_addr *ctx, ipv46_addr_t *dst)
{
	int ret = 1; /* OK value */

	/* do not process anything non-TCP or non-UDP, but do not block it, will be
	 * dealt with somewhere else.
	 */
	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d", ctx->type);
		goto out;
	}

	__u8 ip_proto;
	switch (ctx->type) {
	case SOCK_STREAM:
		CALI_DEBUG("SOCK_STREAM -> assuming TCP");
		ip_proto = IPPROTO_TCP;
		break;
	case SOCK_DGRAM:
		if (CTLB_EXCLUDE_UDP) {
			goto out;
		}
		CALI_DEBUG("SOCK_DGRAM -> assuming UDP");
		ip_proto = IPPROTO_UDP;
		break;
	default:
		CALI_DEBUG("Unknown socket type: %d", (int)ctx->type);
		goto out;
	}

	if (do_nat_common(ctx, ip_proto, dst, true) != 0) {
		ret = 0; /* ret != 1 generates an error in pre-connect */
		goto out;
	}

out:
	return ret;
}

#endif /* __CONNECT_H__ */
