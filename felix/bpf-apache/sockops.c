// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, union ip4_bpf_lpm_trie_key);
    __type(value, __u32);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} calico_sk_endpoints SEC(".maps");

__attribute__((section("calico_sockops_func")))
enum bpf_ret_code calico_sockops(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};
	union ip4_bpf_lpm_trie_key sip, dip;
	__u32 sport, dport;

	switch (skops->op) {
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		/* local app established connection to remote server;
		* fall through */
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		/* remote client connected to local server */
			break;
		default:
		/* other event we don't care about (I wish this was pub/sub!) */
			return BPF_OK;
	}

	ip4val_to_lpm(&sip, 32, skops->local_ip4);
	ip4val_to_lpm(&dip, 32, skops->remote_ip4);

	// If neither source nor dest are present in the Felix-populated endpoints
	// map we do nothing because the packet is not related to Felix-managed
	// traffic.
	if (    NULL == bpf_map_lookup_elem(&calico_sk_endpoints, &dip)
		&&  NULL == bpf_map_lookup_elem(&calico_sk_endpoints, &sip) ) {
		return BPF_OK;
	}

	sport = port_to_host(skops->local_port);
	dport = safe_extract_port(skops->remote_port);

	// We use the app's port and ip address as key. The socket attached
	// to our in-kernel context will be stored as the value automatically.
	if (sip.ip.addr == ENVOY_IP && sport == ENVOY_PORT) {
		// If the source is envoy, the app is on the destination side.
		// We set envoy_side to 1 so the sockmap-attached BPF program
		// (sk_msg in redir.c) can identify packets going to envoy.
		key.envoy_side = 1;
		key.ip4 = dip.ip.addr;
		key.port = dport;
	} else {
		// If the source IP is not envoy we assume it comes from the app (if it
		// doesn't we won't find the socket in the sockmap and pass it to the
		// rest of the stack). We use source port and ip.
		//
		// The destination IP/port is usually never envoy in our testing
		// because we get executed before the destination address is rewritten
		// by iptables so the packet from the app still has the destination
		// address of some other service. We handle the general case.
		key.ip4 = sip.ip.addr;
		key.port = sport;
		key.envoy_side = 0;
	}

	bpf_sock_hash_update(skops, &calico_sock_map, &key, BPF_ANY);

	return BPF_OK;
}

char ____license[] __attribute__((section("license")))  = "Apache-2.0";
