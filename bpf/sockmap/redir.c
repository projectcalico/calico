#include <linux/bpf.h>
#include <iproute2/bpf_elf.h>

#include "sockops.h"

__section("sk_msg")
int calico_sk_msg(struct sk_msg_md *msg)
{
	struct sock_key key = {};
	__u32 sip4, dip4, sport, dport;
	__u64 flags = BPF_F_INGRESS;
	int err;

	dip4 = msg->remote_ip4;
	sip4 = msg->local_ip4;

	// XXX code works with the following workaround, but why does
	// the representation change between sockops and sk_msg?
	//
	// A simple:
	//
	// sport = (bpf_ntohl(msg->local_port) >> 16);
	//
	// should work fine.
	sport = bpf_ntohl(msg->local_port);
	sport = (sport >> 8) | (sport << 8);
	sport = sport & 0xffff;

	// The verifier doesn't seem to like reading something different than
	// 32 bits for these fields:
	//
	// https://github.com/torvalds/linux/commit/303def35f64e37bcd5401d202889f5fbc0241179#diff-ecd5cf968e9720d49c4360acef3e8e32R5160
	//
	// Trick the optimizer to load the full 32 bits
	// instead of only 16.
	dport = (msg->remote_port >> 16) | (msg->remote_port & 0xffff);

	// If the source is envoy, we need to redirect to the socket to the
	// other end. That is, not on the envoy side and with an IP/port
	// matching the destination IP/port.
	if (sip4 == ENVOY_IP && sport == ENVOY_PORT) {
		key.ip4 = dip4;
		key.port = dport;
		key.envoy_side = 0;
	// The destination IP/port is usually never envoy in our testing
	// because we get executed before the destination address is rewritten
	// by iptables so the packet from the app still has the destination
	// address of some other service. We handle the general case.
	//
	// If the source IP is not envoy we assume it comes from the app (if it
	// doesn't we won't find the socket in the sockmap and pass it to the
	// rest of the stack). We need to redirect to the socket envoy is
	// listening on, which is addressed by setting envoy side and the
	// IP/port of the app.
	} else {
		key.ip4 = sip4;
		key.port = sport;
		key.envoy_side = 1;
	}

	err = msg_redirect_hash(msg, &calico_sock_map, &key, flags);

	// If the packet couldn't be redirected, pass it to the rest of the
	// stack.
	return SK_PASS;
}
