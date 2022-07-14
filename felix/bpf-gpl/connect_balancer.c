// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/bpf.h>

// socket_type.h contains the definition of SOCK_XXX constants that we need
// but it's supposed to be imported via socket.h, which we can't import due
// to lack of std lib support for BPF.  Bypass its check for now.
#define _SYS_SOCKET_H
#include <bits/socket_type.h>

#include <stdbool.h>

#include "globals.h"
#include "bpf.h"
#include "log.h"
#include "nat_lookup.h"

#include "sendrecv.h"

#if !defined(__BPFTOOL_LOADER__)
const volatile struct cali_ctlb_globals __globals;
#define UDP_NOT_SEEN_TIMEO __globals.udp_not_seen_timeo
#else
#define UDP_NOT_SEEN_TIMEO 60 /* for tests */
#endif

static CALI_BPF_INLINE int do_nat_common(struct bpf_sock_addr *ctx, __u8 proto, bool connect)
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
	nat_dest = calico_v4_nat_lookup(0, ctx->user_ip4, proto, dport_he, false, &res,
			proto == IPPROTO_UDP && !connect ? UDP_NOT_SEEN_TIMEO : 0, /* enforce affinity UDP */
			proto == IPPROTO_UDP && !connect /* update affinity timer */);
	if (!nat_dest) {
		CALI_INFO("NAT miss.\n");
		if (res == NAT_NO_BACKEND) {
			err = -1;
		}
		goto out;
	}

	__u32 dport_be = host_to_ctx_port(nat_dest->port);

	__u64 cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Store: ip=%x port=%d cookie=%x\n",
			bpf_ntohl(nat_dest->addr), bpf_ntohs((__u16)dport_be), cookie);

	/* For all protocols, record recent NAT operations in an LRU map; other BPF programs use this
	 * cache to reverse our DNAT so they can do pre-DNAT policy. */
	struct ct_nats_key natk = {
		.cookie = cookie,
		.ip = nat_dest->addr,
		.port = dport_be,
		.proto = proto,
	};
	struct sendrecv4_val val = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
	};
	int rc = cali_v4_ct_nats_update_elem(&natk, &val, 0);
	if (rc) {
		/* if this happens things are really bad! report */
		CALI_INFO("Failed to update ct_nats map rc=%d\n", rc);
	}

	if (proto != IPPROTO_TCP) {
		/* For UDP, store a long-lived reverse mapping, which we use to reverse the DNAT for programs that
		 * check the source on the return packets. */
		__u64 cookie = bpf_get_socket_cookie(ctx);
		CALI_DEBUG("Store: ip=%x port=%d cookie=%x\n",
				bpf_ntohl(nat_dest->addr), bpf_ntohs((__u16)dport_be), cookie);
		struct sendrecv4_key key = {
			.ip	= nat_dest->addr,
			.port	= dport_be,
			.cookie	= cookie,
		};

		if (cali_v4_srmsg_update_elem(&key, &val, 0)) {
			/* if this happens things are really bad! report */
			CALI_INFO("Failed to update map\n");
			goto out;
		}
	}

	ctx->user_ip4 = nat_dest->addr;
	ctx->user_port = dport_be;

out:
	return err;
}

SEC("cgroup/connect4")
int calico_connect_v4(struct bpf_sock_addr *ctx)
{
	int ret = 1; /* OK value */

	CALI_DEBUG("calico_connect_v4\n");

	/* do not process anything non-TCP or non-UDP, but do not block it, will be
	 * dealt with somewhere else.
	 */
	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	__u8 ip_proto;
	switch (ctx->type) {
	case SOCK_STREAM:
		CALI_DEBUG("SOCK_STREAM -> assuming TCP\n");
		ip_proto = IPPROTO_TCP;
		break;
	case SOCK_DGRAM:
		CALI_DEBUG("SOCK_DGRAM -> assuming UDP\n");
		ip_proto = IPPROTO_UDP;
		break;
	default:
		CALI_DEBUG("Unknown socket type: %d\n", (int)ctx->type);
		goto out;
	}

	if (do_nat_common(ctx, ip_proto, true) != 0) {
		ret = 0; /* ret != 1 generates an error in pre-connect */
	}

out:
	return ret;
}

SEC("cgroup/sendmsg4")
int calico_sendmsg_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("sendmsg_v4 %x:%d\n",
			bpf_ntohl(ctx->user_ip4), bpf_ntohl(ctx->user_port)>>16);

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	do_nat_common(ctx, IPPROTO_UDP, false);

out:
	return 1;
}

SEC("cgroup/recvmsg4")
int calico_recvmsg_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("recvmsg_v4 %x:%d\n", bpf_ntohl(ctx->user_ip4), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	__u64 cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Lookup: ip=%x port=%d(BE) cookie=%x\n",ctx->user_ip4, ctx->user_port, cookie);
	struct sendrecv4_key key = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
		.cookie	= cookie,
	};

	struct sendrecv4_val *revnat = cali_v4_srmsg_lookup_elem(&key);

	if (revnat == NULL) {
		CALI_DEBUG("revnat miss for %x:%d\n",
				bpf_ntohl(ctx->user_ip4), ctx_port_to_host(ctx->user_port));
		/* we are past policy and the packet was allowed. Either the
		 * mapping does not exist anymore and if the app cares, it
		 * should check the addresses. It is more likely a packet sent
		 * to server from outside and no mapping is expected.
		 */
		goto out;
	}

	ctx->user_ip4 = revnat->ip;
	ctx->user_port = revnat->port;
	CALI_DEBUG("recvmsg_v4 rev nat to %x:%d\n",
			bpf_ntohl(ctx->user_ip4), ctx_port_to_host(ctx->user_port));

out:
	return 1;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
