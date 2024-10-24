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
#include "globals.h"
#include "ctlb.h"
#include "log.h"

#include "sendrecv.h"
#include "connect.h"

#undef debug_ip

#ifdef BPF_CORE_SUPPORTED
#define IP_FMT "[%pI6]"
#define debug_ip(ip) (&(ip))
#else
#define debug_ip(ip) (bpf_htonl((ip)[3]))
#endif

SEC("cgroup/connect6")
int calico_connect_v6(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("calico_connect_v6\n");

	ipv46_addr_t dst = {};
	be32_4_ip_to_ipv6_addr_t(&dst, ctx->user_ip6);

	int ret = connect(ctx, &dst);
	ipv6_addr_t_to_be32_4_ip(ctx->user_ip6, &dst);

	return ret;
}

SEC("cgroup/sendmsg6")
int calico_sendmsg_v6(struct bpf_sock_addr *ctx)
{
	if (CTLB_EXCLUDE_UDP) {
		goto out;
	}

	CALI_DEBUG("sendmsg_v6 " IP_FMT ":%d\n",
			debug_ip(ctx->user_ip6), bpf_ntohl(ctx->user_port)>>16);

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	ipv46_addr_t dst = {};
	be32_4_ip_to_ipv6_addr_t(&dst, ctx->user_ip6);

	do_nat_common(ctx, IPPROTO_UDP, &dst, false);
	ipv6_addr_t_to_be32_4_ip(ctx->user_ip6, &dst);

out:
	return 1;
}

SEC("cgroup/recvmsg6")
int calico_recvmsg_v6(struct bpf_sock_addr *ctx)
{
	if (CTLB_EXCLUDE_UDP) {
		goto out;
	}

	CALI_DEBUG("recvmsg_v6 " IP_FMT ":%d\n", debug_ip(ctx->user_ip6), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	__u64 cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Lookup: ip=" IP_FMT " port=%d(BE) cookie=%x\n", debug_ip(ctx->user_ip6), ctx->user_port, cookie);
	struct sendrec_key key = {
		.port	= ctx->user_port,
		.cookie	= cookie,
	};
	be32_4_ip_to_ipv6_addr_t(&key.ip, ctx->user_ip6);

	struct sendrec_val *revnat = cali_srmsg_lookup_elem(&key);

	if (revnat == NULL) {
		CALI_DEBUG("revnat miss for " IP_FMT ":%d\n",
				debug_ip(ctx->user_ip6), ctx_port_to_host(ctx->user_port));
		/* we are past policy and the packet was allowed. Either the
		 * mapping does not exist anymore and if the app cares, it
		 * should check the addresses. It is more likely a packet sent
		 * to server from outside and no mapping is expected.
		 */
		goto out;
	}

	ipv6_addr_t_to_be32_4_ip(ctx->user_ip6, &revnat->ip);
	ctx->user_port = revnat->port;
	CALI_DEBUG("recvmsg_v6 rev nat to " IP_FMT ":%d\n",
			debug_ip(ctx->user_ip6), ctx_port_to_host(ctx->user_port));

out:
	return 1;
}
