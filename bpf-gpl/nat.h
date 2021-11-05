// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#include <stddef.h>

#include <linux/if_ether.h>
#include <linux/udp.h>

#include "bpf.h"
#include "skb.h"
#include "routes.h"
#include "nat_types.h"

#ifndef CALI_VXLAN_VNI
#define CALI_VXLAN_VNI 0xca11c0
#endif

#define dnat_should_encap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL && !CALI_F_WIREGUARD)
#define dnat_return_should_encap() (CALI_F_FROM_WEP && !CALI_F_TUNNEL && !CALI_F_WIREGUARD)
#define dnat_should_decap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL && !CALI_F_WIREGUARD)

/* Number of bytes we add to a packet when we do encap. */
#define VXLAN_ENCAP_SIZE	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
				sizeof(struct udphdr) + sizeof(struct vxlanhdr))

static CALI_BPF_INLINE int skb_nat_l4_csum_ipv4(struct __sk_buff *skb, size_t off,
						__be32 ip_from, __be32 ip_to,
						__u16 dport_from, __u16 dport_to,
						__u16 sport_from, __u16 sport_to,
						__u64 flags)
{
	int ret = 0;

	if (ip_from != ip_to) {
		CALI_DEBUG("L4 checksum update (csum is at %d) IP from %x to %x\n", off,
				bpf_ntohl(ip_from), bpf_ntohl(ip_to));
		ret = bpf_l4_csum_replace(skb, off, ip_from, ip_to, flags | BPF_F_PSEUDO_HDR | 4);
		CALI_DEBUG("bpf_l4_csum_replace(IP): %d\n", ret);
	}
	if (sport_from != sport_to) {
		CALI_DEBUG("L4 checksum update (csum is at %d) sport from %d to %d\n",
				off, bpf_ntohs(sport_from), bpf_ntohs(sport_to));
		int rc = bpf_l4_csum_replace(skb, off, sport_from, sport_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(sport): %d\n", rc);
		ret |= rc;
	}
	if (dport_from != dport_to) {
		CALI_DEBUG("L4 checksum update (csum is at %d) dport from %d to %d\n",
				off, bpf_ntohs(dport_from), bpf_ntohs(dport_to));
		int rc = bpf_l4_csum_replace(skb, off, dport_from, dport_to, flags | 2);
		CALI_DEBUG("bpf_l4_csum_replace(dport): %d\n", rc);
		ret |= rc;
	}

	return ret;
}

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup2(__be32 ip_src,
								     __be32 ip_dst,
								     __u8 ip_proto,
								     __u16 dport,
								     bool from_tun,
								     nat_lookup_result *res)
{
	struct calico_nat_v4_key nat_key = {
		.prefixlen = NAT_PREFIX_LEN_WITH_SRC_MATCH_IN_BITS,
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
		.saddr = ip_src,
	};
	struct calico_nat_v4_value *nat_lv1_val;
	struct calico_nat_secondary_v4_key nat_lv2_key;
	struct calico_nat_dest *nat_lv2_val;
	struct calico_nat_v4_affinity_key affkey = {};
	__u64 now = 0;

	if (!CALI_F_TO_HOST) {
		// Skip NAT lookup for traffic leaving the host namespace.
		return NULL;
	}

	nat_lv1_val = cali_v4_nat_fe_lookup_elem(&nat_key);
	CALI_DEBUG("NAT: 1st level lookup addr=%x port=%d protocol=%d.\n",
		(int)bpf_ntohl(nat_key.addr), (int)dport,
		(int)(nat_key.protocol));

	if (!nat_lv1_val) {
		struct cali_rt *rt;

		CALI_DEBUG("NAT: Miss.\n");
		/* If the traffic originates at the node (workload or host)
		 * check whether the destination is a remote nodeport to do a
		 * straight NAT and avoid a possible extra hop.
		 */
		if (!(CALI_F_FROM_WEP || CALI_F_TO_HEP || CALI_F_CGROUP ||
					(CALI_F_FROM_HEP && from_tun)) || ip_dst == 0xffffffff) {
			return NULL;
		}

		/* XXX replace the following with a nodeport cidrs lookup once
		 * XXX we have it.
		 */
		rt = cali_rt_lookup(ip_dst);
		if (!rt) {
			CALI_DEBUG("NAT: route miss\n");
			if (!from_tun) {
				return NULL;
			}

			/* we got here because the original node that forwarded
			 * it through the tunnel thought it is a nodeport, we can
			 * use the wildcard nodeport entry.
			 *
			 * If the nodes have multiple IPs/NICs, RT entries would
			 * not know the other IPs of other nodes.
			 *
			 * XXX we might wrongly consider another service IP that
			 * XXX we do not know yet (anymore?) as a nodeport.
			 */
			CALI_DEBUG("NAT: ignore rt lookup miss from tunnel, assume nodeport\n");
		} else if (!cali_rt_is_host(rt)) {
			CALI_DEBUG("NAT: route dest not a host\n");
			return NULL;
		}

		nat_key.addr = 0xffffffff;
		nat_lv1_val = cali_v4_nat_fe_lookup_elem(&nat_key);
		if (!nat_lv1_val) {
			CALI_DEBUG("NAT: nodeport miss\n");
			return NULL;
		}
		CALI_DEBUG("NAT: nodeport hit\n");
	}
	/* With LB source range, we install a drop entry in the NAT FE map
	 * with count equal to 0xffffffff. If we hit this entry,
	 * packet is dropped.
	 */
	if (nat_lv1_val->count == NAT_FE_DROP_COUNT) {
		*res = NAT_FE_LOOKUP_DROP;
		return NULL;
	}
	__u32 count = from_tun ? nat_lv1_val->local : nat_lv1_val->count;

	CALI_DEBUG("NAT: 1st level hit; id=%d\n", nat_lv1_val->id);

	if (count == 0) {
		CALI_DEBUG("NAT: no backend\n");
		*res = NAT_NO_BACKEND;
		return NULL;
	}

	if (nat_lv1_val->affinity_timeo == 0) {
		goto skip_affinity;
	}

	struct calico_nat_v4 nat_data = {
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
	};
	affkey.nat_key = nat_data;
	affkey.client_ip = ip_src;

	CALI_DEBUG("NAT: backend affinity %d seconds\n", nat_lv1_val->affinity_timeo);

	struct calico_nat_v4_affinity_val *affval;

	now = bpf_ktime_get_ns();
	affval = cali_v4_nat_aff_lookup_elem(&affkey);
	if (affval && now - affval->ts <= nat_lv1_val->affinity_timeo * 1000000000ULL) {
		CALI_DEBUG("NAT: using affinity backend %x:%d\n",
				bpf_ntohl(affval->nat_dest.addr), affval->nat_dest.port);

		return &affval->nat_dest;
	}
	CALI_DEBUG("NAT: affinity invalid, new lookup for %x\n", bpf_ntohl(ip_dst));
	/* To be k8s conformant, fall through to pick a random backend. */

skip_affinity:
	nat_lv2_key.id = nat_lv1_val->id;
	nat_lv2_key.ordinal = bpf_get_prandom_u32();
	nat_lv2_key.ordinal %= count;

	CALI_DEBUG("NAT: 1st level hit; id=%d ordinal=%d\n", nat_lv2_key.id, nat_lv2_key.ordinal);

	if (!(nat_lv2_val = cali_v4_nat_be_lookup_elem(&nat_lv2_key))) {
		CALI_DEBUG("NAT: backend miss\n");
		*res = NAT_NO_BACKEND;
		return NULL;
	}

	CALI_DEBUG("NAT: backend selected %x:%d\n", bpf_ntohl(nat_lv2_val->addr), nat_lv2_val->port);

	if (nat_lv1_val->affinity_timeo != 0) {
		int err;
		struct calico_nat_v4_affinity_val val = {
			.ts = now,
			.nat_dest = *nat_lv2_val,
		};

		CALI_DEBUG("NAT: updating affinity for client %x\n", bpf_ntohl(ip_src));
		if ((err = cali_v4_nat_aff_update_elem(&affkey, &val, BPF_ANY))) {
			CALI_INFO("NAT: failed to update affinity table: %d\n", err);
			/* we do carry on, we have a good nat_lv2_val */
		}
	}

	return nat_lv2_val;
}

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup(__be32 ip_src, __be32 ip_dst,
								    __u8 ip_proto, __u16 dport, nat_lookup_result *res)
{
	return calico_v4_nat_lookup2(ip_src, ip_dst, ip_proto, dport, false, res);
}

static CALI_BPF_INLINE int vxlan_v4_encap(struct cali_tc_ctx *ctx,  __be32 ip_src, __be32 ip_dst)
{
	int ret;
	__wsum csum;

	__u32 new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct udphdr) + sizeof(struct vxlanhdr);

	ret = bpf_skb_adjust_room(ctx->skb, new_hdrsz, BPF_ADJ_ROOM_MAC,
						  BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
						  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
						  BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr)));

	if (ret) {
		goto out;
	}

	ret = -1;

	if (skb_refresh_validate_ptrs(ctx, new_hdrsz)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short VXLAN encap\n");
		goto out;
	}

	// Note: assuming L2 packet here so this code can't be used on an L3 device.
	struct vxlanhdr *vxlan = (void *)(tc_udphdr(ctx) + 1);
	struct ethhdr *eth_inner = (void *)(vxlan+1);
	struct iphdr *ip_inner = (void*)(eth_inner+1);

	/* Copy the original IP header. Since it is already DNATed, the dest IP is
	 * already set. All we need to do is to change the source IP
	 */
	*ctx->ip_header = *ip_inner;

	/* decrement TTL for the inner IP header. TTL must be > 1 to get here */
	ip_dec_ttl(ip_inner);

	ctx->ip_header->saddr = ip_src;
	ctx->ip_header->daddr = ip_dst;
	ctx->ip_header->tot_len = bpf_htons(bpf_ntohs(ctx->ip_header->tot_len) + new_hdrsz);
	ctx->ip_header->ihl = 5; /* in case there were options in ip_inner */
	ctx->ip_header->check = 0;
	ctx->ip_header->protocol = IPPROTO_UDP;

	tc_udphdr(ctx)->source = tc_udphdr(ctx)->dest = bpf_htons(VXLAN_PORT);
	tc_udphdr(ctx)->len = bpf_htons(bpf_ntohs(ctx->ip_header->tot_len) - sizeof(struct iphdr));

	*((__u8*)&vxlan->flags) = 1 << 3; /* set the I flag to make the VNI valid */
	vxlan->vni = bpf_htonl(CALI_VXLAN_VNI) >> 8; /* it is actually 24-bit, last 8 reserved */

	/* keep eth_inner MACs zeroed, it is useless after decap */
	eth_inner->h_proto = tc_ethhdr(ctx)->h_proto;

	CALI_DEBUG("vxlan encap %x : %x\n", bpf_ntohl(ctx->ip_header->saddr), bpf_ntohl(ctx->ip_header->daddr));

	/* change the checksums last to avoid pointer access revalidation */

	csum = bpf_csum_diff(0, 0, (void *)ctx->ip_header, sizeof(struct iphdr), 0);
	ret = bpf_l3_csum_replace(ctx->skb, ((long) ctx->ip_header) - ((long) skb_start_ptr(ctx->skb)) +
				  offsetof(struct iphdr, check), 0, csum, 0);

out:
	return ret;
}

static CALI_BPF_INLINE int vxlan_v4_decap(struct __sk_buff *skb)
{
	__u32 extra_hdrsz;
	int ret = -1;

	extra_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct udphdr) + sizeof(struct vxlanhdr);

	ret = bpf_skb_adjust_room(skb, -extra_hdrsz, BPF_ADJ_ROOM_MAC, 0);

	return ret;
}

static CALI_BPF_INLINE int is_vxlan_tunnel(struct iphdr *ip)
{
	struct udphdr *udp = (struct udphdr *)(ip +1);

	return ip->protocol == IPPROTO_UDP &&
		udp->dest == bpf_htons(VXLAN_PORT);
}

static CALI_BPF_INLINE bool vxlan_size_ok(struct cali_tc_ctx *ctx)
{
	return !skb_refresh_validate_ptrs(ctx, UDP_SIZE + sizeof(struct vxlanhdr));
}

static CALI_BPF_INLINE __u32 vxlan_vni(struct cali_tc_ctx *ctx)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(skb, tc_udphdr(ctx));

	return bpf_ntohl(vxlan->vni << 8); /* 24-bit field, last 8 reserved */
}

static CALI_BPF_INLINE bool vxlan_vni_is_valid(struct cali_tc_ctx *ctx)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(ctx->skb, tc_udphdr(ctx));

	return *((__u8*)&vxlan->flags) & (1 << 3);
}

#define vxlan_udp_csum_ok(udp) ((udp)->check == 0)

static CALI_BPF_INLINE bool vxlan_v4_encap_too_big(struct cali_tc_ctx *ctx)
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

/* vxlan_attempt_decap tries to decode the packet as VXLAN and, if it is a BPF-to-BPF
 * program VXLAN packet, does the decap. Returns:
 *
 * 0:  on success (either a packet that doesn't need decap or decap was successful).
 * -1: if the packet was invalid (e.g. too short)
 * -2: if the packet is VXLAN from a Calico host, to this node, but it is not the right VNI.
 */
static CALI_BPF_INLINE int vxlan_attempt_decap(struct cali_tc_ctx *ctx) {
	/* decap on host ep only if directly for the node */
	CALI_DEBUG("VXLAN tunnel packet to %x (host IP=%x)\n",
		bpf_ntohl(ctx->ip_header->daddr),
		bpf_ntohl(HOST_IP));

	if (!rt_addr_is_local_host(ctx->ip_header->daddr)) {
		goto fall_through;
	}
	if (!vxlan_size_ok(ctx)) {
		/* UDP header said VXLAN but packet wasn't long enough. */
		goto deny;
	}
	if (!vxlan_vni_is_valid(ctx) ) {
		goto fall_through;
	}
	if (vxlan_vni(ctx) != CALI_VXLAN_VNI) {
		if (rt_addr_is_remote_host(ctx->ip_header->saddr)) {
			/* Not BPF-generated VXLAN packet but it was from a Calico host to this node. */
			goto auto_allow;
		}
		/* Not our VNI, not from Calico host. Fall through to policy. */
		goto fall_through;
	}
	if (!rt_addr_is_remote_host(ctx->ip_header->saddr)) {
		CALI_DEBUG("VXLAN with our VNI from unexpected source.\n");
		ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
		goto deny;
	}
	if (!vxlan_udp_csum_ok(tc_udphdr(ctx))) {
		/* Our VNI but checksum is incorrect (we always use check=0). */
		CALI_DEBUG("VXLAN with our VNI but incorrect checksum.\n");
		ctx->fwd.reason = CALI_REASON_UNAUTH_SOURCE;
		goto deny;
	}

	ctx->arpk.ip = ctx->ip_header->saddr;
	ctx->arpk.ifindex = ctx->skb->ifindex;

	/* We update the map straight with the packet data, eth header is
	 * dst:src but the value is src:dst so it flips it automatically
	 * when we use it on xmit.
	 */
	cali_v4_arp_update_elem(&ctx->arpk, tc_ethhdr(ctx), 0);
	CALI_DEBUG("ARP update for ifindex %d ip %x\n", ctx->arpk.ifindex, bpf_ntohl(ctx->arpk.ip));

	ctx->state->tun_ip = ctx->ip_header->saddr;
	CALI_DEBUG("vxlan decap\n");
	if (vxlan_v4_decap(ctx->skb)) {
		ctx->fwd.reason = CALI_REASON_DECAP_FAIL;
		goto deny;
	}

	/* Revalidate the packet after the decap. */
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		goto deny;
	}

	CALI_DEBUG("vxlan decap origin %x\n", bpf_ntohl(ctx->state->tun_ip));

fall_through:
	return 0;

auto_allow:
	return -2;

deny:
	ctx->fwd.res = TC_ACT_SHOT;
	return -1;
}

#endif /* __CALI_NAT_H__ */
