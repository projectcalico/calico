// Copyright (c) 2020 Tigera, Inc. All rights reserved.

#include <linux/bpf.h>
#include <sys/socket.h>

#include "../include/bpf.h"
#include "../include/log.h"
#include "../include/nat.h"

__attribute__((section("calico_connect_v4_noop")))
int cali_noop_v4(struct bpf_sock_addr *ctx)
{
	CALI_INFO("Noop program executing\n");
	return 1;
}

static CALI_BPF_INLINE struct calico_nat_dest* nat_lookup(struct bpf_sock_addr *ctx, uint8_t proto)
{
	uint16_t dport = (uint16_t)(be32_to_host(ctx->user_port)>>16);

	/* We do not know what the source address is yet, we only know that it
	 * is the localhost, so we might just use 0.0.0.0. That would not
	 * conflict with traffic from elsewhere.
	 *
	 * XXX it means that all workloads that use the cgroup hook have the
	 * XXX same affinity, which (a) is sub-optimal and (b) leaks info between
	 * XXX workloads.
	 */
	return calico_v4_nat_lookup(0, ctx->user_ip4, proto, dport);
}

static CALI_BPF_INLINE uint16_t ctx_port_to_host(__u32 port)
{
	return be32_to_host(port) >> 16;
}

static CALI_BPF_INLINE __u32 host_to_ctx_port(uint16_t port)
{
	return host_to_be32(((uint32_t)port) << 16);
}

__attribute__((section("calico_connect_v4")))
int cali_ctlb_v4(struct bpf_sock_addr *ctx)
{
	int verdict = 1;

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

	struct calico_nat_dest *nat_dest;

	nat_dest = nat_lookup(ctx, ip_proto);
	if (!nat_dest) {
		goto out;
	}

	ctx->user_ip4 = nat_dest->addr;
	ctx->user_port = host_to_ctx_port(nat_dest->port);

out:
	return verdict;
}

struct sendrecv4_key {
	uint64_t cookie;
	uint32_t ip;
	uint32_t port; /* because bpf_sock_addr uses 32bit and we would need padding */
};

struct sendrecv4_val {
	uint32_t ip;
	uint32_t port; /* because bpf_sock_addr uses 32bit and we would need padding */
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_srmsg = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct sendrecv4_key),
	.value_size = sizeof(struct sendrecv4_val),
	.max_entries = 510000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

__attribute__((section("calico_sendmsg_v4")))
int cali_ctlb_sendmsg_v4(struct bpf_sock_addr *ctx)
{
	CALI_DEBUG("sendmsg_v4 %x:%d\n",
			be32_to_host(ctx->user_ip4), be32_to_host(ctx->user_port)>>16);

	if (ctx->type != SOCK_DGRAM) {
		CALI_INFO("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	struct calico_nat_dest *nat_dest;

	nat_dest = nat_lookup(ctx, IPPROTO_UDP);
	if (!nat_dest) {
		goto out;
	}

	uint32_t dport = host_to_ctx_port(nat_dest->port);

	struct sendrecv4_key key = {
		.ip	= nat_dest->addr,
		.port	= dport,
		.cookie	= bpf_get_socket_cookie(ctx),
	};
	struct sendrecv4_val val = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
		/* XXX we should also store the backend key to verify that it is
		 * XXX still ok upon recvmsg.
		 */
	};

	if (bpf_map_update_elem(&cali_v4_srmsg, &key, &val, 0)) {
		/* if this happens things are really bad! report */
		CALI_INFO("sendmsg4 failed to update map\n");
		goto out;
	}

	ctx->user_ip4 = nat_dest->addr;
	ctx->user_port = dport;

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

	struct sendrecv4_key key = {
		.ip	= ctx->user_ip4,
		.port	= ctx->user_port,
		.cookie	= bpf_get_socket_cookie(ctx),
	};

	struct sendrecv4_val *revnat = bpf_map_lookup_elem(&cali_v4_srmsg, &key);

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
