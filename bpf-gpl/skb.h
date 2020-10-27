// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __SKB_H__
#define __SKB_H__


#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

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

#define skb_len_dir_access(skb) skb_tail_len(skb, skb_start_ptr(skb))

#define skb_seen(skb) ((skb)->mark & CALI_SKB_MARK_SEEN)

#define IPV4_UDP_SIZE		(sizeof(struct iphdr) + sizeof(struct udphdr))
#define ETH_IPV4_UDP_SIZE	(sizeof(struct ethhdr) + IPV4_UDP_SIZE)

static CALI_BPF_INLINE bool skb_too_short(struct __sk_buff *skb)
{
	int min_size;
	if (CALI_F_IPIP_ENCAPPED) {
		min_size = ETH_IPV4_UDP_SIZE + sizeof(struct iphdr);
	} else if (CALI_F_L3) {
		min_size = IPV4_UDP_SIZE;
	} else {
		min_size = ETH_IPV4_UDP_SIZE;
	}
	if (skb_shorter(skb, min_size)) {
		// Try to pull in more data.  Ideally enough for TCP, or, failing that, enough for UDP.
		if (bpf_skb_pull_data(skb, min_size + sizeof(struct tcphdr) - sizeof(struct udphdr))) {
			CALI_DEBUG("Pull failed (TCP len)\n");
			if (bpf_skb_pull_data(skb, min_size)) {
				CALI_DEBUG("Pull failed (UDP len)\n");
				return true;
			}
		}
		CALI_DEBUG("Pulled data\n");
		return skb_shorter(skb, min_size);
	}
	return false;
}

static CALI_BPF_INLINE long skb_iphdr_offset(struct __sk_buff *skb)
{
	if (CALI_F_IPIP_ENCAPPED) {
		// Ingress on an IPIP tunnel: skb is [ether|outer IP|inner IP|payload]
		return sizeof(struct ethhdr) + sizeof(struct iphdr);
	} else if (CALI_F_L3) {
		// Egress on an IPIP tunnel, or Wireguard both directions:
		// skb is [inner IP|payload]
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
	CALI_DEBUG("IP id=%d s=%x d=%x\n",
			be16_to_host(ip->id), be32_to_host(ip->saddr), be32_to_host(ip->daddr));
	return ip;
}

static CALI_BPF_INLINE long skb_l4hdr_offset(struct __sk_buff *skb, __u8 ihl)
{
	return skb_iphdr_offset(skb) + ihl;
}

static CALI_BPF_INLINE __u32 skb_ingress_ifindex(struct __sk_buff *skb)
{
#ifdef UNITTEST
	/* ingress_ifindex is not set in PROG_RUN */
	return skb->ingress_ifindex ? : skb->ifindex;
#else
	return skb->ingress_ifindex;
#endif
}

#define skb_is_gso(skb) ((skb)->gso_segs > 1)

#endif /* __SKB_H__ */
