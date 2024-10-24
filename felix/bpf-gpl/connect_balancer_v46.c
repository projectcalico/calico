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

#define CALI_LOG(fmt, ...) bpf_log("CTLB-V46--------: " fmt, ## __VA_ARGS__)

#include "log.h"

#include "sendrecv.h"
#include "connect.h"

static CALI_BPF_INLINE bool is_ipv4_as_ipv6(__u32 *addr) {
	return addr[0] == 0 && addr[1] == 0 && addr[2] == bpf_htonl(0x0000ffff);
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 3);
	__uint(map_flags, 0);
}cali_ctlb_progs SEC(".maps");

enum cali_ctlb_prog_index {
	PROG_INDEX_V6_CONNECT,
	PROG_INDEX_V6_SENDMSG,
	PROG_INDEX_V6_RECVMSG,
};

SEC("cgroup/connect6")
int calico_connect_v46(struct bpf_sock_addr *ctx)
{
	int ret = 1;
	__be32 ipv4;

#ifdef BPF_CORE_SUPPORTED
	CALI_DEBUG("connect_v46 %pI6", ctx->user_ip6);
#else
	CALI_DEBUG("connect_v46 ip[0-1] %x%x",
			ctx->user_ip6[0],
			ctx->user_ip6[1]);
	CALI_DEBUG("connect_v46 ip[2-3] %x%x",
			ctx->user_ip6[2],
			ctx->user_ip6[3]);
#endif

	if (is_ipv4_as_ipv6(ctx->user_ip6)) {
		goto v4;
	}

	bpf_tail_call(ctx, &cali_ctlb_progs, PROG_INDEX_V6_CONNECT);
	goto out;

v4:
	ipv4 = ctx->user_ip6[3];

 	if ((ret = connect(ctx, &ipv4)) != 1) {
		goto out;
	}

	ctx->user_ip6[3] = ipv4;

out:
	return ret;
}

SEC("cgroup/sendmsg6")
int calico_sendmsg_v46(struct bpf_sock_addr *ctx)
{
	if (CTLB_EXCLUDE_UDP) {
		goto out;
	}

	__be32 ipv4;

#ifdef BPF_CORE_SUPPORTED
	CALI_DEBUG("sendmsg_v46 %pI6", ctx->user_ip6);
#else
	CALI_DEBUG("sendmsg_v46 ip[0-1] %x%x",
			ctx->user_ip6[0],
			ctx->user_ip6[1]);
	CALI_DEBUG("sendmsg_v46 ip[2-3] %x%x",
			ctx->user_ip6[2],
			ctx->user_ip6[3]);
#endif

	if (is_ipv4_as_ipv6(ctx->user_ip6)) {
		goto v4;
	}

	bpf_tail_call(ctx, &cali_ctlb_progs, PROG_INDEX_V6_SENDMSG);
	goto out;

v4:
	ipv4 = ctx->user_ip6[3];
	CALI_DEBUG("sendmsg_v46 " IP_FMT ":%d", debug_ip(ipv4), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d", ctx->type);
		goto out;
	}
	do_nat_common(ctx, IPPROTO_UDP, &ipv4, false);

out:
	return 1;
}

SEC("cgroup/recvmsg6")
int calico_recvmsg_v46(struct bpf_sock_addr *ctx)
{
	if (CTLB_EXCLUDE_UDP) {
		goto out;
	}

	__be32 ipv4;

#ifdef BPF_CORE_SUPPORTED
	CALI_DEBUG("recvmsg_v46 %pI6", ctx->user_ip6);
#else
	CALI_DEBUG("recvmsg_v46 ip[0-1] %x%x",
			ctx->user_ip6[0],
			ctx->user_ip6[1]);
	CALI_DEBUG("recvmsg_v46 ip[2-3] %x%x",
			ctx->user_ip6[2],
			ctx->user_ip6[3]);
#endif

	if (is_ipv4_as_ipv6(ctx->user_ip6)) {
		goto v4;
	}

	bpf_tail_call(ctx, &cali_ctlb_progs, PROG_INDEX_V6_RECVMSG);
	goto out;


v4:
	ipv4 = ctx->user_ip6[3];
	CALI_DEBUG("recvmsg_v46 %x:%d", bpf_ntohl(ipv4), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d", ctx->type);
		goto out;
	}

	struct sendrec_key key = {
		.ip	= ipv4,
		.port	= ctx->user_port,
		.cookie	= bpf_get_socket_cookie(ctx),
	};

	struct sendrec_val *revnat = cali_srmsg_lookup_elem(&key);

	if (revnat == NULL) {
		CALI_DEBUG("revnat miss for " IP_FMT ":%d",
				debug_ip(ipv4), ctx_port_to_host(ctx->user_port));
		/* we are past policy and the packet was allowed. Either the
		 * mapping does not exist anymore and if the app cares, it
		 * should check the addresses. It is more likely a packet sent
		 * to server from outside and no mapping is expected.
		 */
		goto out;
	}

	ctx->user_ip6[3] = revnat->ip;
	ctx->user_port = revnat->port;
	CALI_DEBUG("recvmsg_v46 v4 rev nat to " IP_FMT ":%d",
			debug_ip(ipv4), ctx_port_to_host(ctx->user_port));

out:
	return 1;
}

