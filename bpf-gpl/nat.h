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

typedef enum calico_nat_lookup_result {
	NAT_LOOKUP_ALLOW,
	NAT_FE_LOOKUP_DROP,
	NAT_NO_BACKEND,
} nat_lookup_result;

struct calico_nat_v4 {
        __u32 addr; // NBO
        __u16 port; // HBO
        __u8 protocol;
};

/* Map: NAT level one.  Dest IP, port and src IP -> ID and num backends.
 * Modified the map from HASH to LPM_TRIE. This is to drop packets outside
 * src IP range specified for Load Balancer
 */
struct __attribute__((__packed__)) calico_nat_v4_key {
	__u32 prefixlen;
	__u32 addr; // NBO
	__u16 port; // HBO
	__u8 protocol;
	__u32 saddr;
	__u8 pad;
};

/* Prefix len = (dst_addr + port + protocol + src_addr) in bits. */
#define NAT_PREFIX_LEN_WITH_SRC_MATCH  (sizeof(struct calico_nat_v4_key) - \
					sizeof(((struct calico_nat_v4_key*)0)->prefixlen) - \
					sizeof(((struct calico_nat_v4_key*)0)->pad))

#define NAT_PREFIX_LEN_WITH_SRC_MATCH_IN_BITS (NAT_PREFIX_LEN_WITH_SRC_MATCH * 8)

// This is used as a special ID along with count=0 to drop a packet at nat level1 lookup
#define NAT_FE_DROP_COUNT  0xffffffff

union calico_nat_v4_lpm_key {
        struct bpf_lpm_trie_key lpm;
        struct calico_nat_v4_key key;
};

struct calico_nat_v4_value {
	__u32 id;
	__u32 count;
	__u32 local;
	__u32 affinity_timeo;
};

CALI_MAP(cali_v4_nat_fe, 2,
		BPF_MAP_TYPE_LPM_TRIE,
		union calico_nat_v4_lpm_key, struct calico_nat_v4_value,
		511000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

// Map: NAT level two.  ID and ordinal -> new dest and port.

struct calico_nat_secondary_v4_key {
	__u32 id;
	__u32 ordinal;
};

struct calico_nat_dest {
	__u32 addr;
	__u16 port;
	__u8 pad[2];
};

CALI_MAP_V1(cali_v4_nat_be,
		BPF_MAP_TYPE_HASH,
		struct calico_nat_secondary_v4_key, struct calico_nat_dest,
		510000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

struct calico_nat_v4_affinity_key {
	struct calico_nat_v4 nat_key;
	__u32 client_ip;
	__u32 padding;
};

struct calico_nat_v4_affinity_val {
	struct calico_nat_dest nat_dest;
	__u64 ts;
};

CALI_MAP_V1(cali_v4_nat_aff,
		BPF_MAP_TYPE_LRU_HASH,
		struct calico_nat_v4_affinity_key, struct calico_nat_v4_affinity_val,
		510000, 0, MAP_PIN_GLOBAL)

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

struct vxlanhdr {
	__be32 flags;
	__be32 vni;
};

static CALI_BPF_INLINE int vxlan_v4_encap(struct __sk_buff *skb,  __be32 ip_src, __be32 ip_dst)
{
	int ret;
	__u32 new_hdrsz;
	struct ethhdr *eth, *eth_inner;
	struct iphdr *ip, *ip_inner;
	struct udphdr *udp;
	struct vxlanhdr *vxlan;
	__wsum csum;

	new_hdrsz = sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct udphdr) + sizeof(struct vxlanhdr);

	ret = bpf_skb_adjust_room(skb, new_hdrsz, BPF_ADJ_ROOM_MAC,
						  BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
						  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
						  BPF_F_ADJ_ROOM_ENCAP_L2(sizeof(struct ethhdr)));

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
	*ip = *ip_inner;

	/* decrement TTL for the inner IP header. TTL must be > 1 to get here */
	ip_dec_ttl(ip_inner);

	ip->saddr = ip_src;
	ip->daddr = ip_dst;
	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + new_hdrsz);
	ip->ihl = 5; /* in case there were options in ip_inner */
	ip->check = 0;
	ip->protocol = IPPROTO_UDP;

	udp->source = udp->dest = bpf_htons(CALI_VXLAN_PORT);
	udp->len = bpf_htons(bpf_ntohs(ip->tot_len) - sizeof(struct iphdr));

	*((__u8*)&vxlan->flags) = 1 << 3; /* set the I flag to make the VNI valid */
	vxlan->vni = bpf_htonl(CALI_VXLAN_VNI) >> 8; /* it is actually 24-bit, last 8 reserved */

	/* keep eth_inner MACs zeroed, it is useless after decap */
	eth_inner->h_proto = eth->h_proto;

	CALI_DEBUG("vxlan encap %x : %x\n", bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));

	/* change the checksums last to avoid pointer access revalidation */

	csum = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
	ret = bpf_l3_csum_replace(skb, ((long) ip) - ((long) skb->data) +
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
		udp->dest == bpf_htons(CALI_VXLAN_PORT) &&
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

	return bpf_ntohl(vxlan->vni << 8); /* 24-bit field, last 8 reserved */
}

static CALI_BPF_INLINE bool vxlan_vni_is_valid(struct __sk_buff *skb, struct udphdr *udp)
{
	struct vxlanhdr *vxlan;

	vxlan = skb_ptr_after(skb, udp);

	return *((__u8*)&vxlan->flags) & (1 << 3);
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
