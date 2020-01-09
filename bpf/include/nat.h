// Copyright (c) 2020 Tigera, Inc. All rights reserved.

#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#include <stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>

#include "bpf.h"
#include "routes.h"

#ifndef CALI_VXLAN_PORT
#define CALI_VXLAN_PORT 4789 /* IANA VXLAN port */
#endif

#define dnat_should_encap() (CALI_F_FROM_HEP)
#define dnat_return_should_encap() (CALI_F_FROM_WEP)
#define dnat_should_decap() (CALI_F_FROM_HEP)

#define CALI_ENCAP_EXTRA_SIZE	50

#ifndef CALI_NAT_TUNNEL_MTU
#define CALI_NAT_TUNNEL_MTU	(1500 - CALI_ENCAP_EXTRA_SIZE)
#endif

static CALI_BPF_INLINE __be32 cali_host_ip() {
#ifdef CALI_HOST_IP
	return CALI_HOST_IP;
#endif

	__u32 host_ip;
	// At program install time, we patch in the IP of the host.  Use inline assembler to make sure that the
	// code we want to patch is recognisable.
	// 0x54534f48 = ASCII(HOST).
	asm("%0 = 0x54534f48;" : "=r"(host_ip) /* output */ : /* no inputs */ : /* no clobber */);
	return host_ip;
}

// Map: NAT level one.  Dest IP and port -> ID and num backends.

struct calico_nat_v4_key {
	uint32_t addr; // NBO
	uint16_t port; // HBO
	uint8_t protocol;
	uint8_t pad;
};

struct calico_nat_v4_value {
	uint32_t id;
	uint32_t count;
	uint32_t local;
	uint32_t affinity_timeo;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_nat_fe = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_nat_v4_key),
	.value_size = sizeof(struct calico_nat_v4_value),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 511000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

// Map: NAT level two.  ID and ordinal -> new dest and port.

struct calico_nat_secondary_v4_key {
	uint32_t id;
	uint32_t ordinal;
};

struct calico_nat_dest {
	uint32_t addr;
	uint16_t port;
	uint8_t pad[2];
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_nat_be = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_nat_secondary_v4_key),
	.value_size = sizeof(struct calico_nat_dest),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 510000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

struct calico_nat_v4_affinity_key {
	struct calico_nat_v4_key nat_key;
	uint32_t client_ip;
	uint32_t padding;
};

struct calico_nat_v4_affinity_val {
	struct calico_nat_dest nat_dest;
	uint64_t ts;
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_v4_nat_aff = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct calico_nat_v4_affinity_key),
	.value_size = sizeof(struct calico_nat_v4_affinity_val),
	.max_entries = 510000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup(__be32 ip_src, __be32 ip_dst,
								    __u8 ip_proto, __u16 dport)
{
	struct calico_nat_v4_value *nat_lv1_val;

	if (!CALI_F_TO_HOST) {
		// Skip NAT lookup for traffic leaving the host namespace.
		return NULL;
	}

	struct calico_nat_v4_key nat_key = {
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
	};

	nat_lv1_val = bpf_map_lookup_elem(&cali_v4_nat_fe, &nat_key);
	CALI_DEBUG("NAT: 1st level lookup addr=%x port=%d protocol=%d.\n",
		(int)be32_to_host(nat_key.addr), (int)dport,
		(int)(nat_key.protocol));

	if (!nat_lv1_val) {
		struct calico_route *rt;

		CALI_DEBUG("NAT: Miss.\n");
		/* If the traffic originates at the node (workload or host)
		 * check whether the destination is a remote nodeport to do a
		 * straight NAT and avoid a possible extra hop.
		 */
		if (!(CALI_F_FROM_WEP || CALI_F_TO_HEP || CALI_F_CGROUP) || ip_dst == 0xffffffff) {
			return NULL;
		}

		/* XXX replace the following with a nodeport cidrs lookup once
		 * XXX we have it.
		 */
		rt = cali_rt_lookup(ip_dst);
		if (!rt) {
			CALI_DEBUG("NAT: route miss\n");
			return NULL;
		}

		if (!cali_rt_is_host(rt)) {
			CALI_DEBUG("NAT: route dest not a host\n");
			return NULL;
		}

		nat_key.addr = 0xffffffff;
		nat_lv1_val = bpf_map_lookup_elem(&cali_v4_nat_fe, &nat_key);
		if (!nat_lv1_val) {
			CALI_DEBUG("NAT: nodeport miss\n");
			return NULL;
		}
		CALI_DEBUG("NAT: nodeport hit\n");
	}

	if (nat_lv1_val->count == 0) {
		CALI_DEBUG("NAT: no backend\n");
		return NULL;
	}

	struct calico_nat_secondary_v4_key nat_lv2_key = {
		.id = nat_lv1_val->id,
		.ordinal = bpf_get_prandom_u32() % nat_lv1_val->count,
	};
	struct calico_nat_dest *nat_lv2_val;

	CALI_DEBUG("NAT: 1st level hit; id=%d ordinal=%d\n", nat_lv2_key.id, nat_lv2_key.ordinal);

	if (!(nat_lv2_val = bpf_map_lookup_elem(&cali_v4_nat_be, &nat_lv2_key))) {
		CALI_DEBUG("NAT: backend miss\n");
		return NULL;
	}

	CALI_DEBUG("NAT: backend selected %x:%d\n", be32_to_host(nat_lv2_val->addr), nat_lv2_val->port);

	if (nat_lv1_val->affinity_timeo == 0) {
		return nat_lv2_val;
	}

	CALI_DEBUG("NAT: backend affinity %d seconds\n", nat_lv1_val->affinity_timeo);

	struct calico_nat_v4_affinity_key affkey = {
		.nat_key =  nat_key,
		.client_ip = ip_src,
	};
	struct calico_nat_v4_affinity_val *affval;
	uint64_t now = bpf_ktime_get_ns();

	affval = bpf_map_lookup_elem(&cali_v4_nat_aff, &affkey);
	if (affval == NULL || now - affval->ts > nat_lv1_val->affinity_timeo * 1000000000) {
		int err;
		struct calico_nat_v4_affinity_val val = {
			.ts = now,
			.nat_dest = *nat_lv2_val,
		};

		CALI_DEBUG("NAT: updating affinity for client %x\n", be32_to_host(ip_src));
		if ((err = bpf_map_update_elem(&cali_v4_nat_aff, &affkey, &val, BPF_ANY))) {
			CALI_INFO("NAT: failed to update affinity table: %d\n", err);
			/* we do carry on, we have a good nat_lv2_val */
		}

		return nat_lv2_val;
	}

	CALI_DEBUG("NAT: using affinity backend %x:%d\n",
			be32_to_host(affval->nat_dest.addr), affval->nat_dest.port);

	return &affval->nat_dest;
}

struct vxlanhdr {
	__be32 flags;
	__be32 vni;
};

static CALI_BPF_INLINE int vxlan_v4_encap(struct __sk_buff *skb,  __be32 ip_src, __be32 ip_dst)
{
	int ret;
	uint32_t new_hdrsz;
	struct ethhdr *eth, *eth_inner;
	struct iphdr *ip, *ip_inner;
	struct udphdr *udp;
	struct vxlanhdr *vxlan;
	__wsum csum;

	new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct udphdr) + sizeof(struct vxlanhdr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	ret = bpf_skb_adjust_room(skb, new_hdrsz, BPF_ADJ_ROOM_MAC,
						  BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
						  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
						  BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr)));

#else
	/* XXX if IP options are used, we loose them */
	ret = bpf_skb_adjust_room(skb, new_hdrsz, BPF_ADJ_ROOM_NET, 0);
#endif
	if (ret) {
		goto out;
	}

	ret = -1;

	if skb_shorter(skb, sizeof(struct ethhdr) + new_hdrsz +
			    sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		CALI_DEBUG("VXLAN encap: too short after room adjust\n");
		goto out;
	}

	eth = (void *)(long)skb->data;
	ip = (void*)(eth + 1);
	udp = (void*)(ip + 1);
	vxlan = (void *)(udp +1);
	eth_inner = (void *)(vxlan+1);
	ip_inner = (void*)(eth_inner+1);

	/* Copy the original IP header. Since it is aready DNATed, the dest IP is
	 * already set. All we need to do it to change the source IP
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	*ip = *ip_inner;
#else
	*ip_inner = *ip;
#endif
	ip->saddr = ip_src;
	ip->daddr = ip_dst;
	ip->tot_len = host_to_be16(be16_to_host(ip->tot_len) + new_hdrsz);
	ip->ihl = 5; /* in case there were options in ip_inner */
	ip->check = 0;
	ip->protocol = IPPROTO_UDP;

	udp->source = udp->dest = host_to_be16(CALI_VXLAN_PORT);
	udp->len = host_to_be16(skb_tail_len(skb, udp));

	/* set the I flag to make the VNI valid, keep the VNI 0-ed */
	*((uint8_t*)&vxlan->flags) = 1 << 3;

	/* keep eth_inner MACs zeroed, it is useless after decap */
	eth_inner->h_proto = eth->h_proto;

	CALI_DEBUG("vxlan encap %x : %x\n", be32_to_host(ip->saddr), be32_to_host(ip->daddr));

	/* change the checksums last to avoid pointer access revalidation */

	csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
	ret = bpf_l3_csum_replace(skb, ((long) ip) - ((long) skb->data) +
				  offsetof(struct iphdr, check), 0, csum, 0);

out:
	return ret;
}

static CALI_BPF_INLINE int vxlan_v4_decap(struct __sk_buff *skb)
{
	uint32_t extra_hdrsz;
	int ret = -1;

	extra_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
		sizeof(struct udphdr) + sizeof(struct vxlanhdr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	ret = bpf_skb_adjust_room(skb, -extra_hdrsz, BPF_ADJ_ROOM_MAC, 0);
#else
	if skb_shorter(skb, sizeof(struct ethhdr) + extra_hdrsz +
			    sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		CALI_DEBUG_NO_FLAG("VXLAN decap: too short\n");
		goto out;
	}

	struct iphdr *ip, *ip_inner;

	ip = skb_ptr(skb, sizeof(struct ethhdr));
	ip_inner = skb_ptr(skb, sizeof(struct ethhdr) +extra_hdrsz);

	/* restore the header */
	*ip = *ip_inner;

	ret =  bpf_skb_adjust_room(skb, -extra_hdrsz, BPF_ADJ_ROOM_NET, 0);

out:

#endif

	return ret;
}

static CALI_BPF_INLINE int is_vxlan_tunnel(struct iphdr *ip)
{
	struct udphdr *udp = (struct udphdr *)(ip +1);

	return ip->protocol == IPPROTO_UDP && udp->dest == host_to_be16(CALI_VXLAN_PORT);
}

#define vxlan_v4_encap_too_big(skb) ((skb)->len + CALI_ENCAP_EXTRA_SIZE > CALI_NAT_TUNNEL_MTU)

static CALI_BPF_INLINE int icmp_v4_too_big(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	struct iphdr *ip, ip_orig;
	struct icmphdr *icmp;
	uint32_t len;
	__wsum ip_csum, icmp_csum;
	int ret;

	eth = skb_start_ptr(skb);
	ip = skb_ptr_after(skb, eth);

	CALI_DEBUG_NO_FLAG("ip->ihl: %d\n", ip->ihl);
	if (ip->ihl > 5) {
		CALI_DEBUG_NO_FLAG("ICMP too big: IP options\n");
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
		CALI_DEBUG_NO_FLAG("ICMP too big: failed to make room\n");
		return -1;
	}

	/* ICMP reply carries the IP header + 8 bytes of data */
	len += sizeof(struct ethhdr) + sizeof(struct iphdr) + 8;

	if (skb_shorter(skb, len)) {
		CALI_DEBUG_NO_FLAG("ICMP too big: too short after making room\n");
		return -1;
	}

	/* N.B. getting the ip pointer here again makes verifier happy */
	eth = skb_start_ptr(skb);
	ip = skb_ptr_after(skb, eth);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
	struct iphdr *ip_inner;

	if (skb_shorter(skb, ip_inner_off + sizeof(struct iphdr))) {
		CALI_DEBUG_NO_FLAG("ICMP too big: too short to move ip header\n");
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
	ip->ttl = 64; /* good defaul */
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->tot_len = host_to_be16(len - sizeof(struct ethhdr));

#ifdef CALI_PARANOID
	/* XXX verify that ip_orig.daddr is always the node's IP
	 *
	 * we only call this function because of NodePOrt encap
	 */
	if (ip_orig.daddr != cali_host_ip()) {
		CALI_DEBUG_NO_FLAG("ICMP too big: ip_orig.daddr != cali_host_ip() 0x%x\n", ip_orig.daddr);
	}
#endif
	ip->saddr = ip_orig.daddr;
	ip->daddr = ip_orig.saddr;

	icmp = skb_ptr_after(skb, ip);
	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_FRAG_NEEDED;
	icmp->un.frag.mtu = host_to_be16(CALI_NAT_TUNNEL_MTU);
	icmp->checksum = 0;

	ip_csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
	icmp_csum = bpf_csum_diff(0, 0, (void *)icmp, sizeof(*icmp) + sizeof(struct iphdr) + 8 , 0);

	ret = bpf_l3_csum_replace(skb,
			skb_offset(skb, ip) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG_NO_FLAG("ICMP too big: set ip csum failed\n");
		return -1;
	}

	if (skb_shorter(skb, len)) {
		CALI_DEBUG_NO_FLAG("ICMP too big: too short after ip csum fix\n");
		return -1;
	}

	ret = bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
					offsetof(struct icmphdr, checksum), 0, icmp_csum, 0);
	if (ret) {
		CALI_DEBUG_NO_FLAG("ICMP too big: set icmp csum failed\n");
		return -1;
	}

	/* trim the packet to the desired length */
	if (bpf_skb_change_tail(skb, len,  0)) {
		return -1;
	}

	return 0;
}

#endif /* __CALI_NAT_H__ */
