// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/bpf.h>

// socket_type.h contains the definition of SOCK_XXX constants that we need
// but it's supposed to be imported via socket.h, which we can't import due
// to lack of std lib support for BPF.  Bypass its check for now.
#define _SYS_SOCKET_H
#include <bits/socket_type.h>

#include <stdbool.h>

#include "globals.h"
#include "ctlb.h"
#include "bpf.h"
#include "log.h"

#include "sendrecv.h"
#include "connect.h"

SEC("cgroup/connect4")
int calico_connect_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("calico_connect_v4\n");

	return connect(ctx, &ctx->user_ip4);
}

SEC("cgroup/sendmsg4")
int calico_sendmsg_v4(struct bpf_sock_addr *ctx)
{
	if (CTLB_EXCLUDE_UDP) {
		goto out;
	}

	CALI_DEBUG("sendmsg_v4 %x:%d\n",
			bpf_ntohl(ctx->user_ip4), bpf_ntohl(ctx->user_port)>>16);

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	do_nat_common(ctx, IPPROTO_UDP, &ctx->user_ip4, false);

out:
	return 1;
}

SEC("cgroup/recvmsg4")
int calico_recvmsg_v4(struct bpf_sock_addr *ctx)
{
	if (CTLB_EXCLUDE_UDP) {
		goto out;
	}

	CALI_DEBUG("recvmsg_v4 " IP_FMT" :%d\n", debug_ip(ctx->user_ip4), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	__u64 cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Lookup: ip=" IP_FMT " port=%d(BE) cookie=%x\n",debug_ip(ctx->user_ip4), ctx->user_port, cookie);
	struct sendrec_key key = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
		.cookie	= cookie,
	};

	struct sendrec_val *revnat = cali_srmsg_lookup_elem(&key);

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
	CALI_DEBUG("recvmsg_v4 rev nat to " IP_FMT ":%d\n",
			debug_ip(ctx->user_ip4), ctx_port_to_host(ctx->user_port));

out:
	return 1;
}
