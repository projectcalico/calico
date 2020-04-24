// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include <linux/bpf.h>
#include <sys/socket.h>

#include "bpf.h"
#include "log.h"
#include "nat.h"

#include "sendrecv.h"

__attribute__((section("calico_connect_v4_noop")))
int cali_noop_v4(struct bpf_sock_addr *ctx)
{
	CALI_INFO("Noop program executing\n");
	return 1;
}

static CALI_BPF_INLINE void do_nat_common(struct bpf_sock_addr *ctx, uint8_t proto)
{
	/* We do not know what the source address is yet, we only know that it
	 * is the localhost, so we might just use 0.0.0.0. That would not
	 * conflict with traffic from elsewhere.
	 *
	 * XXX it means that all workloads that use the cgroup hook have the
	 * XXX same affinity, which (a) is sub-optimal and (b) leaks info between
	 * XXX workloads.
	 */
	uint16_t dport_he = (uint16_t)(be32_to_host(ctx->user_port)>>16);
	struct calico_nat_dest *nat_dest;
	nat_dest = calico_v4_nat_lookup(0, ctx->user_ip4, proto, dport_he);
	if (!nat_dest) {
		CALI_INFO("NAT miss.\n");
		goto out;
	}

	uint32_t dport_be = host_to_ctx_port(nat_dest->port);

	uint64_t cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Store: ip=%x port=%d(BE) cookie=%x\n", nat_dest->addr, dport_be, cookie);
	struct sendrecv4_key key = {
		.ip	= nat_dest->addr,
		.port	= dport_be,
		.cookie	= cookie,
	};
	struct sendrecv4_val val = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
		/* XXX we should also store the backend key to verify that it is
		 * XXX still ok upon recvmsg.
		 */
	};

	if (cali_v4_srmsg_update_elem(&key, &val, 0)) {
		/* if this happens things are really bad! report */
		CALI_INFO("Failed to update map\n");
		goto out;
	}

	ctx->user_ip4 = nat_dest->addr;
	ctx->user_port = dport_be;

out:
	return;
}

__attribute__((section("calico_connect_v4")))
int cali_ctlb_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("calico_connect_v4\n");

	/* do not process anything non-TCP or non-UDP, but do not block it, will be
	 * dealt with somewhere else.
	 */
	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	uint8_t ip_proto;
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

	do_nat_common(ctx, ip_proto);

out:
	return 1;
}

__attribute__((section("calico_sendmsg_v4")))
int cali_ctlb_sendmsg_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("sendmsg_v4 %x:%d\n",
			be32_to_host(ctx->user_ip4), be32_to_host(ctx->user_port)>>16);

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	do_nat_common(ctx, IPPROTO_UDP);

out:
	return 1;
}

__attribute__((section("calico_recvmsg_v4")))
int cali_ctlb_recvmsg_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("recvmsg_v4 %x:%d\n", be32_to_host(ctx->user_ip4), ctx_port_to_host(ctx->user_port));

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	uint64_t cookie = bpf_get_socket_cookie(ctx);
	CALI_DEBUG("Lookup: ip=%x port=%d(BE) cookie=%x",ctx->user_ip4, ctx->user_port, cookie);
	struct sendrecv4_key key = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
		.cookie	= cookie,
	};

	struct sendrecv4_val *revnat = cali_v4_srmsg_lookup_elem(&key);

	if (revnat == NULL) {
		CALI_DEBUG("revnat miss for %x:%d\n",
				be32_to_host(ctx->user_ip4), ctx_port_to_host(ctx->user_port));
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
			be32_to_host(ctx->user_ip4), ctx_port_to_host(ctx->user_port));

out:
	return 1;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
