#include <linux/bpf.h>
#include <iproute2/bpf_elf.h>
#include <sys/socket.h>
#include <stddef.h>

#include "sockops.h"

struct endpoint_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct endpoint_info {
	__u8 dummy;
};

struct bpf_elf_map __section(ELF_SECTION_MAPS) endpoints = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .size_key       = sizeof(struct endpoint_key),
    .size_value     = sizeof(struct endpoint_info),
    .flags          = BPF_F_NO_PREALLOC,
    .max_elem       = 65535,
};

static inline struct endpoint_info *lookup_endpoint(uint32_t ip)
{
	struct endpoint_key key;
	__builtin_memcpy(key.lpm.data, &ip, sizeof(key.addr));
	key.lpm.prefixlen = 32;

	return map_lookup_elem(&endpoints, &key);
}

static inline int has_endpoint(uint32_t ip)
{
	return lookup_endpoint(ip) != NULL;
}

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};
	__u32 sip4, dip4, sport, dport;

	dip4 = skops->remote_ip4;
	sip4 = skops->local_ip4;

	sport = (bpf_ntohl(skops->local_port) >> 16);
	// The verifier doesn't seem to like reading something different than
	// 32 bits for these fields:
	//
	// https://github.com/torvalds/linux/commit/303def35f64e37bcd5401d202889f5fbc0241179#diff-ecd5cf968e9720d49c4360acef3e8e32R5160
	//
	// Trick the optimizer to load the full 32 bits
	// instead of only 16.
	dport = (skops->remote_port >> 16) | (skops->remote_port & 0xffff);

	if (!has_endpoint(sip4) && !has_endpoint(dip4)) {
		return;
	}

	// If the source is envoy, we store the envoy socket with the IP of the
	// app (destination) and set envoy side so the sk_msg program can
	// identify packets going to envoy (see redir.c).
	if (sip4 == ENVOY_IP && sport == ENVOY_PORT) {
		key.ip4 = dip4;
		key.port = dport;
		key.envoy_side = 1;
	// The destination IP/port is usually never envoy in our testing
	// because we get executed before the destination address is rewritten
	// by iptables so the packet from the app still has the destination
	// address of some other service. We handle the general case.
	//
	// If the source IP is not envoy we assume the connection comes from
	// the app. If it doesn't, we'll be storing an unnecessary socket in
	// the sockmap, but this should not really happen since we only care
	// about connections with workload IPs and all connections from the app
	// are redirected to envoy.
	//
	// We store the app socket with the IP of the app (source) and with
	// envoy side set to 0 so the sk_msg program can redirect packets going
	// to the app (see redir.c).
	} else {
		key.ip4 = sip4;
		key.port = sport;
		key.envoy_side = 0;
	}

	sock_hash_update(skops, &calico_sock_map, &key, BPF_ANY);
}

__section("sockops")
int calico_sockops(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			bpf_sock_ops_ipv4(skops);
		break;
	default:
		break;
	}

	return 0;
}
