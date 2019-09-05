#include <linux/bpf.h>
#include <sys/socket.h>

#include "connect_balancer_maps.h"
#include "bpf.h"

#define DEBUG

#ifdef DEBUG
#define LOG(fmt, ...) printk("CONNECT BALANCER : "fmt, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

char ____license[] __attribute__((section("license"), used)) = "GPL";

	__section("cgroup/connect4")
int connect_balancer(struct bpf_sock_addr *ctx)
{
	struct vip_info *vip = NULL;
	ipv4_t ip = bpf_ntohl(ctx->user_ip4);
	ipv4_t *real_ip = NULL;
	struct backend_key bkey;
	int verdict = 1;

	/* do not process anything non-TCP or non-UDP, but do not block it, will be
	 * dealt with somewhere else.
	 */
	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM) {
		LOG("unexpected sock type %d\n", ctx->type);
		goto out;
	}

	vip = map_lookup_elem(&vip_info_map_v4, &ip);
	if (!vip) {
		LOG("no VIP record for 0x%0x\n");
		goto out;
	}

	bkey.vip_id = vip->id;
	bkey.order = get_prandom_u32() % vip->count;

	real_ip = map_lookup_elem(&vip_backends_map_v4, &bkey);

	if (!real_ip) {
		LOG("missing backend for vip 0x%x\n", ip);
		verdict = 0;
		goto out;
	}

	ctx->user_ip4 = bpf_htonl(*real_ip);

out:
	if (verdict && real_ip)
		LOG("connect redirected from vip 0x%x to 0x%x\n", ip, *real_ip);
	else
		LOG("no redirection for ip 0x%x\n", ip);
	return verdict;
}
