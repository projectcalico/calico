#ifndef __CALI_NAT_H__
#define __CALI_NAT_H__

#include <stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/version.h>
#import "bpf.h"

#ifndef CALI_HOST_IP
#define CALI_HOST_IP 0x0
#endif

#ifndef CALI_VXLAN_PORT
#define CALI_VXLAN_PORT 4789 /* IANA VXLAN port */
#endif

#define dnat_should_encap(flags) \
	(CALI_TC_FLAGS_FROM_HOST_ENDPOINT(flags))

#define dnat_return_should_encap(flags) \
	(CALI_TC_FLAGS_FROM_WORKLOAD(flags))

#define dnat_should_decap(flags) \
	(CALI_TC_FLAGS_TO_WORKLOAD(flags) || CALI_TC_FLAGS_FROM_HOST_ENDPOINT(flags))

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
};

struct bpf_map_def_extended __attribute__((section("maps"))) cali_nat_v4 = {
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

struct bpf_map_def_extended __attribute__((section("maps"))) cali_natbe_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct calico_nat_secondary_v4_key),
	.value_size = sizeof(struct calico_nat_dest),
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 510000, // arbitrary
#ifndef __BPFTOOL_LOADER__
	.pinning_strategy = 2 /* global namespace */,
#endif
};

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup(__u8 ip_proto, __be32 ip_dst, __u16 dport,
	enum calico_tc_flags flags) {
	if (((flags & CALI_TC_HOST_EP) && !(flags & CALI_TC_INGRESS)) ||
		(!(flags & CALI_TC_HOST_EP) && (flags & CALI_TC_INGRESS))) {
		// Skip NAT lookup for traffic leaving the host namespace.
		return NULL;
	}

	struct calico_nat_v4_key nat_key = {
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
	};

	struct calico_nat_v4_value *nat_lv1_val = bpf_map_lookup_elem(&cali_nat_v4, &nat_key);
	CALI_DEBUG("NAT: 1st level lookup addr=%x port=%d protocol=%d.\n",
		(int)be32_to_host(nat_key.addr), (int)dport,
		(int)(nat_key.protocol));
	if (!nat_lv1_val) {
		CALI_DEBUG("NAT: Miss.\n");
		return NULL;
	}

	struct calico_nat_secondary_v4_key nat_lv2_key = {
		.id = nat_lv1_val->id,
		.ordinal = bpf_get_prandom_u32() % nat_lv1_val->count,
	};
	CALI_DEBUG("NAT: 1st level hit; id=%d ordinal=%d\n", nat_lv2_key.id, nat_lv2_key.ordinal);
	struct calico_nat_dest *nat_lv2_val = bpf_map_lookup_elem(&cali_natbe_v4,
		&nat_lv2_key);
	if (nat_lv2_val) {
		CALI_DEBUG("NAT: backend selected %x:%d\n", be32_to_host(nat_lv2_val->addr), nat_lv2_val->port);
	} else {
		CALI_DEBUG("NAT: backend miss\n");
	}
	return nat_lv2_val;
}

struct vxlanhdr {
	__be32 flags;
	__be32 vni;
};

static CALI_BPF_INLINE int vxlan_v4_encap(struct __sk_buff *skb,
					  __be32 ipaddr,
					  bool is_src,
					  enum calico_tc_flags flags)
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
	*(is_src ? &ip->saddr : &ip->daddr) = ipaddr;
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

#endif /* __CALI_NAT_H__ */
