// Copyright (c) 2020 Tigera, Inc. All rights reserved.
  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>

#include "sockops.h"

__attribute__((section("calico_sk_msg_func")))
enum sk_action calico_sk_msg(struct sk_msg_md *msg)
{
	struct sock_key key = {};
	__u32 sip, sport, dip, dport;
	int err;

	dip = msg->remote_ip4;
	sip = msg->local_ip4;

	sport = port_to_host(msg->local_port);
	dport = safe_extract_port(msg->remote_port);

	if (sip == ENVOY_IP && sport == ENVOY_PORT) {
	// If the source is envoy, we need to redirect to the socket to the
	// other end. That is, not on the envoy side and with an IP/port
	// matching the destination IP/port.
		key.ip4 = dip;
		key.port = dport;
		key.envoy_side = 0;
	} else {
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
		key.ip4 = sip;
		key.port = sport;
		key.envoy_side = 1;
	}

	err = bpf_msg_redirect_hash(msg, &calico_sock_map, &key, BPF_REDIR_INGRESS);

	// If the packet couldn't be redirected, pass it to the rest of the
	// stack.
	return SK_PASS;
}

char ____license[] __attribute__((section("license")))  = "Apache-2.0";
