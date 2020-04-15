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

#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>

#include "bpf.h"
#include "skb.h"
#include "routes.h"

#ifndef CALI_VXLAN_PORT
#define CALI_VXLAN_PORT 4789 /* IANA VXLAN port */
#endif

#ifndef CALI_VXLAN_VNI
#define CALI_VXLAN_VNI 0xca11c0
#endif

#define dnat_should_encap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL)
#define dnat_return_should_encap() (CALI_F_FROM_WEP && !CALI_F_TUNNEL)
#define dnat_should_decap() (CALI_F_FROM_HEP && !CALI_F_TUNNEL)

/* Number of bytes we add to a packet when we do encap. */
#define VXLAN_ENCAP_SIZE	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
				sizeof(struct udphdr) + sizeof(struct vxlanhdr))

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

/* fast hash by Bob Jenkins suitable for modulo
 * http://burtleburtle.net/bob/hash/integer.html
 */
static CALI_BPF_INLINE uint32_t nat_aff_ip_hash(uint32_t a)
{
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);
    return a;
}

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup2(__be32 ip_src,
								     __be32 ip_dst,
								     __u8 ip_proto,
								     __u16 dport,
								     bool from_tun)
{
	struct calico_nat_v4_key nat_key = {
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
	};
	struct calico_nat_v4_value *nat_lv1_val;
	struct calico_nat_secondary_v4_key nat_lv2_key;
	struct calico_nat_dest *nat_lv2_val;
	struct calico_nat_v4_affinity_key affkey = {};
	uint64_t now = 0;

	if (!CALI_F_TO_HOST) {
		// Skip NAT lookup for traffic leaving the host namespace.
		return NULL;
	}

	nat_lv1_val = bpf_map_lookup_elem(&cali_v4_nat_fe, &nat_key);
	CALI_DEBUG("NAT: 1st level lookup addr=%x port=%d protocol=%d.\n",
		(int)be32_to_host(nat_key.addr), (int)dport,
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

	uint32_t count = from_tun ? nat_lv1_val->local : nat_lv1_val->count;

	CALI_DEBUG("NAT: 1st level hit; id=%d\n", nat_lv1_val->id);

	if (count == 0) {
		CALI_DEBUG("NAT: no backend\n");
		return NULL;
	}

	if (nat_lv1_val->affinity_timeo == 0) {
		goto skip_affinity;
	}

	affkey.nat_key =  nat_key;
	affkey.client_ip = ip_src;

	CALI_DEBUG("NAT: backend affinity %d seconds\n", nat_lv1_val->affinity_timeo);

	struct calico_nat_v4_affinity_val *affval;

	now = bpf_ktime_get_ns();
	affval = bpf_map_lookup_elem(&cali_v4_nat_aff, &affkey);
	if (affval && now - affval->ts <= nat_lv1_val->affinity_timeo * 1000000000ULL) {
		CALI_DEBUG("NAT: using affinity backend %x:%d\n",
				be32_to_host(affval->nat_dest.addr), affval->nat_dest.port);

		return &affval->nat_dest;
	}
	CALI_DEBUG("NAT: affinity invalid, new lookup for %x\n", be32_to_host(ip_dst));

skip_affinity:
	nat_lv2_key.id = nat_lv1_val->id;
	if (nat_lv1_val->affinity_timeo == 0) {
		nat_lv2_key.ordinal = bpf_get_prandom_u32();
	} else {
		/* primitive stable hash, dest ip:port are constant, source port
		 * must not be considered so we use the source ip only. That
		 * means the same client always picks the same ordinal as long
		 * as the backends did not change. When they change, they
		 * may reshuffle or the modulo changes.
		 *
		 * There is a slight race when affinity expires and the backends
		 * change at the same time. There is no guarantee what goes
		 * first anyway.
		 *
		 * Different clients likely pick different backends.
		 */
		nat_lv2_key.ordinal = nat_aff_ip_hash(ip_src);
	}
	nat_lv2_key.ordinal %= count;

	CALI_DEBUG("NAT: 1st level hit; id=%d ordinal=%d\n", nat_lv2_key.id, nat_lv2_key.ordinal);

	if (!(nat_lv2_val = bpf_map_lookup_elem(&cali_v4_nat_be, &nat_lv2_key))) {
		CALI_DEBUG("NAT: backend miss\n");
		return NULL;
	}

	CALI_DEBUG("NAT: backend selected %x:%d\n", be32_to_host(nat_lv2_val->addr), nat_lv2_val->port);

	if (nat_lv1_val->affinity_timeo != 0) {
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
	}

	return nat_lv2_val;
}

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup(__be32 ip_src, __be32 ip_dst,
								    __u8 ip_proto, __u16 dport)
{
	return calico_v4_nat_lookup2(ip_src, ip_dst, ip_proto, dport, false);
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

	if (skb_shorter(skb, sizeof(struct ethhdr) + new_hdrsz +
			    sizeof(struct ethhdr) + sizeof(struct iphdr))) {
		CALI_DEBUG("VXLAN encap: too short after room adjust\n");
		goto out;
	}

	eth = (void *)(long)skb->data;
	ip = (void*)(eth + 1);
	udp = (void*)(ip + 1);
	vxlan = (void *)(udp +1);
	eth_inner = (void *)(vxlan+1);
	ip_inner = (void*)(eth_inner+1);

	/* Copy the original IP header. Since it is already DNATed, the dest IP is
	 * already set. All we need to do is to change the source IP
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
	*ip = *ip_inner;
#else
	*ip_inner = *ip;
#endif

	/* decrement TTL for the inner IP header. TTL must be > 1 to get here */
	ip_dec_ttl(ip_inner);

	ip->saddr = ip_src;
	ip->daddr = ip_dst;
	ip->tot_len = host_to_be16(be16_to_host(ip->tot_len) + new_hdrsz);
	ip->ihl = 5; /* in case there were options in ip_inner */
	ip->check = 0;
	ip->protocol = IPPROTO_UDP;

	udp->source = udp->dest = host_to_be16(CALI_VXLAN_PORT);
	udp->len = host_to_be16(be16_to_host(ip->tot_len) - sizeof(struct iphdr));

	*((uint8_t*)&vxlan->flags) = 1 << 3; /* set the I flag to make the VNI valid */
	vxlan->vni = host_to_be32(CALI_VXLAN_VNI) >> 8; /* it is actually 24-bit, last 8 reserved */

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
	if (skb_shorter(skb, sizeof(struct ethhdr) + extra_hdrsz +
			    sizeof(struct ethhdr) + sizeof(struct iphdr))) {
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

	return ip->protocol == IPPROTO_UDP &&
		udp->dest == host_to_be16(CALI_VXLAN_PORT) &&
		udp->check == 0;
}

static CALI_BPF_INLINE bool vxlan_size_ok(struct __sk_buff *skb, struct udphdr *udp)
{
	return skb_has_data_after(skb, udp, sizeof(struct vxlanhdr));
}

static CALI_BPF_INLINE __u32 vxlan_vni(struct __sk_buff *skb, struct udphdr *udp)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(skb, udp);

	return be32_to_host(vxlan->vni << 8); /* 24-bit field, last 8 reserved */
}

static CALI_BPF_INLINE bool vxlan_vni_is_valid(struct __sk_buff *skb, struct udphdr *udp)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(skb, udp);

	return *((uint8_t*)&vxlan->flags) & (1 << 3);
}

#define vxlan_udp_csum_ok(udp) ((udp)->check == 0)

static CALI_BPF_INLINE bool vxlan_v4_encap_too_big(struct __sk_buff *skb)
{
	__u32 mtu = TUNNEL_MTU;

	/* RFC-1191: MTU is the size in octets of the largest datagram that
	 * could be forwarded, along the path of the original datagram, without
	 * being fragmented at this router.  The size includes the IP header and
	 * IP data, and does not include any lower-level headers.
	 */
	if (skb->len > sizeof(struct ethhdr) + mtu) {
		CALI_DEBUG("SKB too long (len=%d) vs limit=%d\n", skb->len, mtu);
		return true;
	}
	return false;
}

#endif /* __CALI_NAT_H__ */
