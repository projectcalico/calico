// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#ifndef CALI_VXLAN_VNI
#define CALI_VXLAN_VNI 0xca11c0
#endif

#define vxlan_udp_csum_ok(udp) ((udp)->check == 0)

#ifdef IPVER6
#include "nat6.h"
#else
#include "nat4.h"
#endif

#define dnat_should_encap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV && !CALI_F_NAT_IF)
#define dnat_return_should_encap() (CALI_F_FROM_WEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV && !CALI_F_NAT_IF)
#define dnat_should_decap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL && !CALI_F_L3_DEV && !CALI_F_NAT_IF)

static CALI_BPF_INLINE int is_vxlan_tunnel(struct cali_tc_ctx *ctx, __u16 vxlanport)
{
	return ctx->state->ip_proto == IPPROTO_UDP &&
		ctx->state->dport == vxlanport;
}

static CALI_BPF_INLINE bool vxlan_encap_too_big(struct cali_tc_ctx *ctx)
{
	__u32 mtu = TUNNEL_MTU;

	/* RFC-1191: MTU is the size in octets of the largest datagram that
	 * could be forwarded, along the path of the original datagram, without
	 * being fragmented at this router.  The size includes the IP header and
	 * IP data, and does not include any lower-level headers.
	 */
	if (ctx->skb->len > sizeof(struct ethhdr) + mtu) {
		CALI_DEBUG("SKB too long (len=%d) vs limit=%d\n", ctx->skb->len, mtu);
		return true;
	}
	return false;
}

#define EFAULT	14

static CALI_BPF_INLINE int skb_nat_l4_csum(struct cali_tc_ctx *ctx, size_t off,
					   ipv46_addr_t ip_src_from, ipv46_addr_t ip_src_to,
					   ipv46_addr_t ip_dst_from, ipv46_addr_t ip_dst_to,
					   __u16 dport_from, __u16 dport_to,
					   __u16 sport_from, __u16 sport_to,
					   __u64 flags,
					   bool inner_icmp)
{
	int ret = 0;
	struct __sk_buff *skb = ctx->skb;

	if (!inner_icmp) {
		/* Write back L4 header. */
		if (ctx->ipheader_len == IP_SIZE) {
			if (ctx->state->ip_proto == IPPROTO_TCP) {
				if (skb_refresh_validate_ptrs(ctx, TCP_SIZE)) {
					deny_reason(ctx, CALI_REASON_SHORT);
					CALI_DEBUG("Too short\n");
					return -EFAULT;
				}
				__builtin_memcpy(((void*)ip_hdr(ctx))+IP_SIZE, ctx->scratch->l4, TCP_SIZE);
			} else {
				if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
					deny_reason(ctx, CALI_REASON_SHORT);
					CALI_DEBUG("Too short\n");
					return -EFAULT;
				}
				__builtin_memcpy(((void*)ip_hdr(ctx))+IP_SIZE, ctx->scratch->l4, UDP_SIZE);
			}
		} else {
			int size = l4_hdr_len(ctx);
			int offset = skb_l4hdr_offset(ctx);

			if (size == 0) {
				CALI_DEBUG("Bad L4 proto\n");
				return -EFAULT;
			}
			if (bpf_skb_store_bytes(ctx->skb, offset, ctx->scratch->l4, size, 0)) {
				CALI_DEBUG("Too short\n");
				return -EFAULT;
			}
		}
	}

	/* We start with csum == 0 (seed for the first diff) as we are calculating just
	 * the diff between 2 IPs. We then feed the result as a seed to the next diff if
	 * we need to as a carry-over.
	 *
	 * We must use diff because the replace functions cannot calculate a diff for 16
	 * byte ipv6 addresses in one go. And this keeps the code the same for v4/6 with
	 * minimal impact on v4.
	 */
	__wsum csum = 0;

	bool csum_update = false;

	if (!ip_equal(ip_src_from, ip_src_to)) {
		CALI_DEBUG("L4 checksum update src IP from " IP_FMT " to " IP_FMT "\n",
				debug_ip(ip_src_from), debug_ip(ip_src_to));

		csum = bpf_csum_diff((__u32*)&ip_src_from, sizeof(ip_src_from), (__u32*)&ip_src_to, sizeof(ip_src_to), csum);
		CALI_DEBUG("bpf_l4_csum_diff(IP): 0x%x\n", csum);
		csum_update = true;
	}
	if (!ip_equal(ip_dst_from, ip_dst_to)) {
		CALI_DEBUG("L4 checksum update dst IP from " IP_FMT " to " IP_FMT "\n",
				debug_ip(ip_dst_from), debug_ip(ip_dst_to));
		csum = bpf_csum_diff((__u32*)&ip_dst_from, sizeof(ip_dst_from), (__u32*)&ip_dst_to, sizeof(ip_dst_to), csum);
		CALI_DEBUG("bpf_l4_csum_diff(IP): 0x%x\n", csum);
		csum_update = true;
	}

	/* If the IPs have changed we must replace it as part of the pseudo header that is
	 * used to calculate L4 csum.
	 *
	 * If we are fixing inner ICMP payload, we do not change L4 csum for the payload
	 * (no need for that, it is just a fraction of the packet), but the L4 here is the
	 * ICMP itself since its payload has changed. ICMPv4 does not include the pseudo
	 * header in the csum and v6 had it already fixed when we modified the outer IP.
	 */
	if (csum_update) {
		ret = bpf_l4_csum_replace(skb, off, 0, csum, flags | (inner_icmp ? 0 : BPF_F_PSEUDO_HDR));
	}

	/* We can use replace for ports in both v4/6 as they are the same size of 2 bytes. */
	if (sport_from != sport_to) {
		CALI_DEBUG("L4 checksum update sport from %d to %d\n",
				bpf_ntohs(sport_from), bpf_ntohs(sport_to));
		int rc = bpf_l4_csum_replace(skb, off, sport_from, sport_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(sport): %d\n", rc);
		ret |= rc;
	}
	if (dport_from != dport_to) {
		CALI_DEBUG("L4 checksum update dport from %d to %d\n",
				bpf_ntohs(dport_from), bpf_ntohs(dport_to));
		int rc = bpf_l4_csum_replace(skb, off, dport_from, dport_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(dport): %d\n", rc);
		ret |= rc;
	}

	return ret;
}

/* vxlan_attempt_decap tries to decode the packet as VXLAN and, if it is a BPF-to-BPF
 * program VXLAN packet, does the decap. Returns:
 *
 * 0:  on success (either a packet that doesn't need decap or decap was successful).
 * -1: if the packet was invalid (e.g. too short)
 * -2: if the packet is VXLAN from a Calico host, to this node, but it is not the right VNI.
 */
static CALI_BPF_INLINE int vxlan_attempt_decap(struct cali_tc_ctx *ctx)
{
	/* decap on host ep only if directly for the node */
	CALI_DEBUG("VXLAN tunnel packet to " IP_FMT " (host IP=" IP_FMT ")\n",
#ifdef IPVER6
		bpf_ntohl(ip_hdr(ctx)->daddr.in6_u.u6_addr32[3]),
#else
		bpf_ntohl(ip_hdr(ctx)->daddr),
#endif
		debug_ip(HOST_IP));

	if (!rt_addr_is_local_host((ipv46_addr_t *)&ip_hdr(ctx)->daddr)) {
		goto fall_through;
	}
	if (!vxlan_size_ok(ctx)) {
		/* UDP header said VXLAN but packet wasn't long enough. */
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}
	if (!vxlan_vni_is_valid(ctx) ) {
		CALI_DEBUG("VXLAN: Invalid VNI\n");
		goto fall_through;
	}
	if (vxlan_vni(ctx) != CALI_VXLAN_VNI) {
		if (rt_addr_is_remote_host((ipv46_addr_t *)&ip_hdr(ctx)->saddr)) {
			/* Not BPF-generated VXLAN packet but it was from a Calico host to this node. */
			CALI_DEBUG("VXLAN: non-tunnel calico\n");
			goto auto_allow;
		}
		/* Not our VNI, not from Calico host. Fall through to policy. */
		CALI_DEBUG("VXLAN: Not our VNI\n");
		goto fall_through;
	}
	if (!rt_addr_is_remote_host((ipv46_addr_t *)&ip_hdr(ctx)->saddr)) {
		CALI_DEBUG("VXLAN with our VNI from unexpected source.\n");
		deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
		goto deny;
	}
	if (!vxlan_udp_csum_ok(udp_hdr(ctx))) {
		/* Our VNI but checksum is incorrect (we always use check=0). */
		CALI_DEBUG("VXLAN with our VNI but incorrect checksum.\n");
		deny_reason(ctx, CALI_REASON_UNAUTH_SOURCE);
		goto deny;
	}

	/* We update the map straight with the packet data, eth header is
	 * dst:src but the value is src:dst so it flips it automatically
	 * when we use it on xmit.
	 */
	struct arp_key arpk = {
		.ifindex = ctx->skb->ifindex,
	};
#ifdef IPVER6
	ipv6hdr_ip_to_ipv6_addr_t(&arpk.ip, &ip_hdr(ctx)->saddr);
#else
	arpk.ip = ip_hdr(ctx)->saddr;
#endif
	cali_arp_update_elem(&arpk, eth_hdr(ctx), 0);
	CALI_DEBUG("ARP update for ifindex %d ip " IP_FMT "\n", arpk.ifindex, debug_ip(arpk.ip));

#ifdef IPVER6
	ipv6hdr_ip_to_ipv6_addr_t(&ctx->state->tun_ip, &ip_hdr(ctx)->saddr);
#else
	ctx->state->tun_ip = ip_hdr(ctx)->saddr;
#endif
	CALI_DEBUG("vxlan decap\n");
	if (vxlan_decap(ctx->skb)) {
		deny_reason(ctx, CALI_REASON_DECAP_FAIL);
		goto deny;
	}

	/* Revalidate the packet after the decap. */
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		deny_reason(ctx, CALI_REASON_SHORT);
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	CALI_DEBUG("vxlan decap origin " IP_FMT "\n", debug_ip(ctx->state->tun_ip));

fall_through:
	return 0;

auto_allow:
	return -2;

deny:
	ctx->fwd.res = TC_ACT_SHOT;
	return -1;
}


#endif /* __CALI_NAT_H__ */
