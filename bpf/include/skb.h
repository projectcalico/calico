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

#ifndef __SKB_H__
#define __SKB_H__


#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "bpf.h"
#include "log.h"

#define skb_start_ptr(skb) ((void *)(long)(skb)->data)
#define skb_shorter(skb, len) ((void *)(long)(skb)->data + (len) > (void *)(long)skb->data_end)
#define skb_offset(skb, ptr) ((long)(ptr) - (long)(skb)->data)
#define skb_has_data_after(skb, ptr, size) (!skb_shorter(skb, skb_offset(skb, ptr) + \
					     sizeof(*ptr) + (size)))
#define skb_tail_len(skb, ptr) ((skb)->data_end - (long)ptr)
#define skb_ptr(skb, off) ((void *)((long)(skb)->data + (off)))
#define skb_ptr_after(skb, ptr) ((void *)((ptr) + 1))

#define IPV4_UDP_SIZE		(sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_IPV4_UDP_SIZE	(sizeof(struct ethhdr) + IPV4_UDP_SIZE)

static CALI_BPF_INLINE bool skb_too_short(struct __sk_buff *skb)
{
	if (CALI_F_IPIP_ENCAPPED) {
		return skb_shorter(skb, ETH_IPV4_UDP_SIZE + sizeof(struct iphdr));
	} else if (CALI_F_L3) {
		return skb_shorter(skb, IPV4_UDP_SIZE);
	} else {
		return skb_shorter(skb, ETH_IPV4_UDP_SIZE);
	}
	// TODO Deal with IP header with options.
}

static CALI_BPF_INLINE long skb_iphdr_offset(struct __sk_buff *skb)
{
	if (CALI_F_IPIP_ENCAPPED) {
		// Ingress on an IPIP tunnel: skb is [ether|outer IP|inner IP|payload]
		return sizeof(struct ethhdr) + sizeof(struct iphdr);
	} else if (CALI_F_L3) {
		// Egress on an IPIP tunnel: skb is [inner IP|payload]
		return 0;
	} else {
		// Normal L2 interface: skb is [ether|IP|payload]
		return sizeof(struct ethhdr);
	}
}

static CALI_BPF_INLINE struct iphdr *skb_iphdr(struct __sk_buff *skb)
{
	long offset = skb_iphdr_offset(skb);
	struct iphdr *ip = skb_ptr(skb, offset);
	CALI_DEBUG("IP@%d; s=%x d=%x\n", offset, be32_to_host(ip->saddr), be32_to_host(ip->daddr));
	return ip;
}

#endif /* __SKB_H__ */
