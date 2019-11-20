#include <linux/bpf.h>
#include <sys/socket.h>

#include "../include/bpf.h"
#include "../include/log.h"
#include "../include/nat.h"

__attribute__((section("calico_connect_v4_noop")))
int connect_noop(struct bpf_sock_addr *ctx)
{
	enum calico_tc_flags flags = CALI_CGROUP;
	CALI_INFO("Noop program executing\n");
	return 1;
}

__attribute__((section("calico_connect_v4")))
int connect_balancer(struct bpf_sock_addr *ctx)
{
	enum calico_tc_flags flags = CALI_CGROUP;
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
	struct calico_nat_dest *nat_dest = calico_v4_nat_lookup(ip_proto, ctx->user_ip4, dport, flags);
	if (!nat_dest) {
		goto out;
	}

	ctx->user_ip4 = nat_dest->addr;
	ctx->user_port = host_to_be32(((uint32_t)nat_dest->port)<<16);

out:
	return verdict;
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
