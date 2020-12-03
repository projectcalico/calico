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

static CALI_BPF_INLINE int icmp_v4_reply(struct __sk_buff *skb, struct iphdr *ip,
					__u8 type, __u8 code, __be32 un)
{
	struct iphdr ip_orig = *ip;
	struct icmphdr *icmp;
	__u32 len;
	__wsum ip_csum, icmp_csum;
	int ret;
	
	CALI_DEBUG("ip->ihl: %d\n", ip->ihl);
	if (ip->ihl > 5) {
		CALI_DEBUG("ICMP v4 reply: IP options\n");
		return -1;
	}
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
        
	/* make room for the new IP + ICMP header */
	int new_hdrs_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
	ret = bpf_skb_adjust_room(skb, new_hdrs_len, BPF_ADJ_ROOM_MAC, 0);
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

	/* we do not touch ethhdr, we rely on linux to rewrite it after routing
	 * XXX we might want to swap MACs and bounce it back from the same device
	 */
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->ttl = 64; /* good default */
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->tot_len = bpf_htons(len - sizeof(struct ethhdr));

#ifdef CALI_PARANOID
	/* XXX verify that ip_orig.daddr is always the node's IP
	 *
	 * we only call this function because of NodePort encap
	 */
	if (ip_orig.daddr != HOST_IP) {
		CALI_DEBUG("ICMP v4 reply: ip_orig.daddr != HOST_IP 0x%x\n", ip_orig.daddr);
	}
#endif

	/* use the host IP of the program that handles the packet */
	ip->saddr = HOST_IP;
	ip->daddr = ip_orig.saddr;

	icmp = skb_ptr_after(skb, ip);
	icmp->type = type;
	icmp->code = code;
	*((__be32 *)&icmp->un) = un;
	icmp->checksum = 0;

	ip_csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
	icmp_csum = bpf_csum_diff(0, 0, (void *)icmp, len -  sizeof(*ip) - skb_iphdr_offset(skb), 0);

	ret = bpf_l3_csum_replace(skb,
			skb_offset(skb, ip) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG("ICMP v4 reply: set ip csum failed\n");
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
		.mtu = bpf_htons(TUNNEL_MTU),
	};

	CALI_DEBUG("Sending ICMP too big mtu=%d\n", bpf_ntohs(frag.mtu));
	
	/* check to make the verifier happy */
	if (skb_too_short(skb)) {
		CALI_DEBUG("ICMP v4 too big: too short before making room\n");
		return -1;
	}
	struct iphdr *ip = skb_iphdr(skb); 
	return icmp_v4_reply(skb, ip, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, *(__be32 *)&frag);
}

static CALI_BPF_INLINE int icmp_v4_ttl_exceeded(struct __sk_buff *skb)
{
	struct iphdr *ip = skb_iphdr(skb); 
	return icmp_v4_reply(skb, ip, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
}

static CALI_BPF_INLINE int icmp_v4_port_unreachable(struct __sk_buff *skb)
{
	struct iphdr *ip = skb_iphdr(skb);
	return icmp_v4_reply(skb, ip, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
}

static CALI_BPF_INLINE bool icmp_type_is_err(__u8 type)
{
	switch (type) {
	case ICMP_DEST_UNREACH:
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		return true;
	}

	return false;
}

static CALI_BPF_INLINE bool icmp_skb_get_hdr(struct __sk_buff *skb, struct icmphdr **icmp)
{
	struct iphdr *ip;
	long ip_off;
	int minsz;

	ip_off = skb_iphdr_offset(skb);
	minsz = ip_off + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

	if (skb_shorter(skb, minsz)) {
		CALI_DEBUG("ICMP: %d shorter than %d\n", skb_len_dir_access(skb), minsz);
		return false;
	}

	ip = skb_iphdr(skb);

	if (ip->ihl != 5) {
		CALI_INFO("ICMP: ip options unsupported\n");
		return false;
	}

	*icmp = (struct icmphdr *)(ip + 1);

	return true;
}

#endif /* __CALI_ICMP_H__ */
