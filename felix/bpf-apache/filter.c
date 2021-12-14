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

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "filter.h"

CALI_BPF_INLINE static int extract_ports(__u32 len, struct iphdr * h,
	struct protoport *dport)
{
	struct tcphdr * thdr;
	struct udphdr * uhdr;

	dport->proto = h->protocol;

	switch (h->protocol) {
		case IPPROTO_TCP:
			// Re-check buffer space for TCP (has larger headers than UDP).
			if (len <
				sizeof(struct ethhdr) + sizeof(*h) + sizeof(struct tcphdr)) {
				return 1; // Or maybe drop the packet? It's broken anyways.
			}

			thdr = (void*)((__u64)(h) + sizeof(*h));
			dport->port = port_to_host(thdr->dest);
			break;
		case IPPROTO_UDP:
			uhdr = (void*)((__u64)(h) + sizeof(*h));
			dport->port = port_to_host(uhdr->dest);
			break;
		default:
			// Neither TCP nor UDP
			return 0;
	}

	return 1;
}


__attribute__((section("prefilter_func")))
enum xdp_action prefilter(struct xdp_md* xdp)
{
	struct ethhdr * ehdr;
	struct iphdr  * ihdr;
	struct protoport dport = {0,0};
	union ip4_bpf_lpm_trie_key sip;

	// You must be at least 'UDP header' tall to take this ride.
	if (xdp->data + sizeof(*ehdr) + sizeof(*ihdr) + sizeof(struct udphdr)
		> xdp->data_end) {
		// Packet too small to contain ethernet, ip, and UDP headers. Drop.
		return XDP_DROP;
	}

	// Make sure it's an IP packet
	// NOTE that this is a straightforward implementation that
	// does not handle e.g. V[X]LAN encapsulation.
	ehdr = (void*)(long)xdp->data;
	if (be16_to_host(ETH_P_IP) != ehdr->h_proto) {
		return XDP_PASS;
	}

	// Parse l4 protocols and ports.
	// NOTE that this is a straightforward implementation that
	// does not handle e.g. IPIP encapsulation.
	ihdr = (void*)((__u64)(ehdr) + sizeof(*ehdr));
	if (extract_ports(xdp->data_end - xdp->data, ihdr, &dport)) {
		// Check failsafe ports and XDP_PASS early
		if (NULL != bpf_map_lookup_elem(&calico_failsafe_ports, &dport)) {
			return XDP_PASS;
		}
	}

	ip4val_to_lpm(&sip, 32, ihdr->saddr);

	// Drop the packet if source IP matches a blacklist entry.
	if (NULL != bpf_map_lookup_elem(&calico_prefilter_v4, &sip)) {
		// In blacklist - "thou shall not XDP_PASS!"
		return XDP_DROP;
	}

	// Not in blacklist - pass.
	return XDP_PASS;
}

char ____license[] __attribute__((section("license")))  = "Apache-2.0";
