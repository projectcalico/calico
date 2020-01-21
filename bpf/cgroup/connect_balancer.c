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

	uint16_t dport = (uint16_t)(be32_to_host(ctx->user_port)>>16);
	struct calico_nat_dest *nat_dest;

	/* We do not know what the source address is yet, we only know that it
	 * is the localhost, so we might just use 0.0.0.0. That would not
	 * conflict with traffic from elsewhere.
	 *
	 * XXX it means that all workloads that use the cgroup hook have the
	 * XXX same affinity, which (a) is sub-optimal and (b) leaks info between
	 * XXX workloads.
	 */
	nat_dest = calico_v4_nat_lookup(0, ctx->user_ip4, ip_proto, dport);
	if (!nat_dest) {
		goto out;
	}

	ctx->user_ip4 = nat_dest->addr;
	ctx->user_port = host_to_be32(((uint32_t)nat_dest->port)<<16);

out:
	return verdict;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
