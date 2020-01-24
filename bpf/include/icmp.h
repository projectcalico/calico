// Copyright (c) 2020 Tigera, Inc. All rights reserved.

#ifndef __CALI_ICMP_H__
#define __CALI_ICMP_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/version.h>

#include "bpf.h"
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
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: too short after making room\n");
		return -1;
	}

	ip = skb_iphdr(skb);

	CALI_DEBUG_NO_FLAG("ip->ihl: %d\n", ip->ihl);
	if (ip->ihl > 5) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: IP options\n");
		return -1;
	}

	ip_orig = *ip;

	/* make room for the new IP + ICMP header */
	len = sizeof(struct iphdr) + sizeof(struct icmphdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	ret = bpf_skb_adjust_room(skb, len, BPF_ADJ_ROOM_MAC, 0);
#else
	uint32_t ip_inner_off = sizeof(struct ethhdr) + len;
	ret = bpf_skb_adjust_room(skb, len, BPF_ADJ_ROOM_NET, 0);
#endif
	if (ret) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: failed to make room\n");
		return -1;
	}

	/* ICMP reply carries the IP header + 8 bytes of data */
	len += sizeof(struct ethhdr) + sizeof(struct iphdr) + 8;

	if (skb_shorter(skb, len)) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: too short after making room\n");
		return -1;
	}

	/* N.B. getting the ip pointer here again makes verifier happy */
	ip = skb_iphdr(skb);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
	struct iphdr *ip_inner;

	if (skb_shorter(skb, ip_inner_off + sizeof(struct iphdr))) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: too short to move ip header\n");
		return -1;
	}

	/* copy the ip orig header into the icmp data */
	ip_inner = skb_ptr(skb, ip_inner_off);
	*ip_inner = ip_orig;
#endif

	/* we do not touch ethhdr, we rely on linux to rewrite it after routing */
	/* XXX we might want to swap MACs and bounce it back from the same device */

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
	 * we only call this function because of NodePOrt encap
	 */
	if (ip_orig.daddr != cali_host_ip()) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: ip_orig.daddr != cali_host_ip() 0x%x\n", ip_orig.daddr);
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
	icmp_csum = bpf_csum_diff(0, 0, (void *)icmp, sizeof(*icmp) + sizeof(struct iphdr) + 8 , 0);

	ret = bpf_l3_csum_replace(skb,
			skb_offset(skb, ip) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: set ip csum failed\n");
		return -1;
	}

	if (skb_shorter(skb, len)) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: too short after ip csum fix\n");
		return -1;
	}

	ret = bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
					offsetof(struct icmphdr, checksum), 0, icmp_csum, 0);
	if (ret) {
		CALI_DEBUG_NO_FLAG("ICMP v4 reply: set icmp csum failed\n");
		return -1;
	}

	/* trim the packet to the desired length */
	if (bpf_skb_change_tail(skb, len,  0)) {
		return -1;
	}

	return 0;
}

static CALI_BPF_INLINE int icmp_v4_too_big(struct __sk_buff *skb)
{
	struct {
		__be16  unused;
		__be16  mtu;
	} frag = {
		.mtu = host_to_be16(CALI_NAT_TUNNEL_MTU),
	};

	return icmp_v4_reply(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, *(__be32 *)&frag);
}

static CALI_BPF_INLINE int icmp_v4_ttl_exceeded(struct __sk_buff *skb)
{
	return icmp_v4_reply(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
}

#endif /* __CALI_ICMP_H__ */
