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

#include "bpf.h"
#include "log.h"

#include "sendrecv.h"
#include "connect.h"

SEC("cgroup/connect6")
int calico_connect_v6(struct bpf_sock_addr *ctx)
{
	int ret = 1;
	__be32 ipv4;

	CALI_DEBUG("connect_v6 ip[0-1] %x%x\n",
			ctx->user_ip6[0],
			ctx->user_ip6[1]);
	CALI_DEBUG("connect_v6 ip[2-3] %x%x\n",
			ctx->user_ip6[2],
			ctx->user_ip6[3]);

	/* check if it is a IPv4 mapped as IPv6 and if so, use the v4 table */
	if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
			ctx->user_ip6[2] == bpf_htonl(0x0000ffff)) {
		goto v4;
	}

	CALI_DEBUG("connect_v6: not implemented for v6 yet\n");
	goto out;

v4:
	ipv4 = ctx->user_ip6[3];

 	if ((ret = connect_v4(ctx, &ipv4)) != 1) {
		goto out;
	}

	ctx->user_ip6[3] = ipv4;

out:
	return ret;
}

SEC("cgroup/sendmsg6")
int calico_sendmsg_v6(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("sendmsg_v6\n");

	return 1;
}

SEC("cgroup/recvmsg6")
int calico_recvmsg_v6(struct bpf_sock_addr *ctx)
{
	__be32 ipv4;

	CALI_DEBUG("recvmsg_v6 ip[0-1] %x%x\n",
			ctx->user_ip6[0],
			ctx->user_ip6[1]);
	CALI_DEBUG("recvmsg_v6 ip[2-3] %x%x\n",
			ctx->user_ip6[2],
			ctx->user_ip6[3]);

	/* check if it is a IPv4 mapped as IPv6 and if so, use the v4 table */
	if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
			ctx->user_ip6[2] == bpf_htonl(0x0000ffff)) {
		goto v4;
	}

	CALI_DEBUG("recvmsg_v6: not implemented for v6 yet\n");
	goto out;


v4:
	ipv4 = ctx->user_ip6[3];
	CALI_DEBUG("recvmsg_v6 %x:%d\n", bpf_ntohl(ipv4), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	struct sendrecv4_key key = {
		.ip	= ipv4,
		.port	= ctx->user_port,
		.cookie	= bpf_get_socket_cookie(ctx),
	};

	struct sendrecv4_val *revnat = cali_v4_srmsg_lookup_elem(&key);

	if (revnat == NULL) {
		CALI_DEBUG("revnat miss for %x:%d\n",
				bpf_ntohl(ipv4), ctx_port_to_host(ctx->user_port));
		/* we are past policy and the packet was allowed. Either the
		 * mapping does not exist anymore and if the app cares, it
		 * should check the addresses. It is more likely a packet sent
		 * to server from outside and no mapping is expected.
		 */
		goto out;
	}

	ctx->user_ip6[3] = revnat->ip;
	ctx->user_port = revnat->port;
	CALI_DEBUG("recvmsg_v6 v4 rev nat to %x:%d\n",
			bpf_ntohl(ipv4), ctx_port_to_host(ctx->user_port));

out:
	return 1;
}


char ____license[] __attribute__((section("license"), used)) = "GPL";
