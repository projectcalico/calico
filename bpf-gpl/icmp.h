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

#ifndef __CALI_ICMP_H__
#define __CALI_ICMP_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "bpf.h"
#include "log.h"
#include "skb.h"

static CALI_BPF_INLINE int icmp_v4_reply(struct __sk_buff *skb,
					 uint8_t type, uint8_t code, __be32 un)
{
	struct iphdr *ip, ip_orig;
	struct icmphdr *icmp;
	uint32_t len;
	__wsum ip_csum, icmp_csum;
	int ret;

	if (skb_too_short(skb)) {
		CALI_DEBUG("ICMP v4 reply: too short before making room\n");
		return -1;
	}

	ip = skb_iphdr(skb);

	CALI_DEBUG("ip->ihl: %d\n", ip->ihl);
	if (ip->ihl > 5) {
		CALI_DEBUG("ICMP v4 reply: IP options\n");
		return -1;
	}

	ip_orig = *ip;

	/* Trim the packet to the desired length. ICMP requires min 8 bytes of
	 * payload but the SKB implementation gets upset if we try to trim
	 * part-way through the UDP/TCP header.
	 */
	len = sizeof(struct ethhdr) + sizeof(struct iphdr) + 64;
	switch (ip->protocol) {
	case IPPROTO_TCP:
		len += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		len += sizeof(struct udphdr);
		break;
	default:
		len += 8;
		break;
	}

	int err = bpf_skb_change_tail(skb, len,  0);
	if (err) {
		CALI_DEBUG("ICMP v4 reply: early bpf_skb_change_tail (len=%d) failed (err=%d)\n", len, err);
		return -1;
	}

	// Revalidate.
	if (skb_too_short(skb)) {
		CALI_DEBUG("ICMP v4 reply: too short after trimming packet\n");
		return -1;
	}

	/* make room for the new IP + ICMP header */
	int new_hdrs_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	ret = bpf_skb_adjust_room(skb, new_hdrs_len, BPF_ADJ_ROOM_MAC, 0);
#else
	uint32_t ip_inner_off = sizeof(struct ethhdr) + len;
	ret = bpf_skb_adjust_room(skb, new_hdrs_len, BPF_ADJ_ROOM_NET, 0);
#endif
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: failed to make room\n");
		return -1;
	}

	/* ICMP reply carries the IP header + at least 8 bytes of data. */
	len += new_hdrs_len;

	if (skb_shorter(skb, len)) {
		CALI_DEBUG("ICMP v4 reply: too short after making room\n");
		return -1;
	}

	/* N.B. getting the ip pointer here again makes verifier happy */
	ip = skb_iphdr(skb);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
	struct iphdr *ip_inner;

	if (skb_shorter(skb, ip_inner_off + sizeof(struct iphdr))) {
		CALI_DEBUG("ICMP v4 reply: too short to move ip header\n");
		return -1;
	}

	/* copy the ip orig header into the icmp data */
	ip_inner = skb_ptr(skb, ip_inner_off);
	*ip_inner = ip_orig;
#endif

	/* we do not touch ethhdr, we rely on linux to rewrite it after routing
	 * XXX we might want to swap MACs and bounce it back from the same device
	 */
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->ttl = 64; /* good default */
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->tot_len = host_to_be16(len - sizeof(struct ethhdr));

#ifdef CALI_PARANOID
	/* XXX verify that ip_orig.daddr is always the node's IP
	 *
	 * we only call this function because of NodePort encap
	 */
	if (ip_orig.daddr != cali_host_ip()) {
		CALI_DEBUG("ICMP v4 reply: ip_orig.daddr != cali_host_ip() 0x%x\n", ip_orig.daddr);
	}
#endif

	/* use the host IP of the program that handles the packet */
	ip->saddr = cali_host_ip();
	ip->daddr = ip_orig.saddr;

	icmp = skb_ptr_after(skb, ip);
	icmp->type = type;
	icmp->code = code;
	*((__be32 *)&icmp->un) = un;
	icmp->checksum = 0;

	ip_csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
	icmp_csum = bpf_csum_diff(0, 0, (void *)icmp, len -  sizeof(*ip) - sizeof(struct ethhdr), 0);

	ret = bpf_l3_csum_replace(skb,
			skb_offset(skb, ip) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set ip csum failed\n");
		return -1;
	}

	if (skb_shorter(skb, len)) {
		CALI_DEBUG("ICMP v4 reply: too short after ip csum fix\n");
		return -1;
	}

	ret = bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
					offsetof(struct icmphdr, checksum), 0, icmp_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set icmp csum failed\n");
		return -1;
	}

	CALI_DEBUG("ICMP v4 reply creation succeeded\n");

	return 0;
}

static CALI_BPF_INLINE int icmp_v4_too_big(struct __sk_buff *skb)
{
	struct {
		__be16  unused;
		__be16  mtu;
	} frag = {
		.mtu = host_to_be16(TUNNEL_MTU),
	};

	CALI_DEBUG("Sending ICMP too big mtu=%d\n", be16_to_host(frag.mtu));

	return icmp_v4_reply(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, *(__be32 *)&frag);
}

static CALI_BPF_INLINE int icmp_v4_ttl_exceeded(struct __sk_buff *skb)
{
	return icmp_v4_reply(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
}

#endif /* __CALI_ICMP_H__ */
