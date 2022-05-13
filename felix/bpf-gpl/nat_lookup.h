// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_NAT_LOOKUP_H__
#define __CALI_NAT_LOOKUP_H__

#include <stddef.h>

#include <linux/if_ether.h>
#include <linux/udp.h>

#include "bpf.h"
#include "routes.h"
#include "nat_types.h"

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup(__be32 ip_src,
								    __be32 ip_dst,
								    __u8 ip_proto,
								    __u16 dport,
								    bool from_tun,
								    nat_lookup_result *res,
								    int affinity_always_timeo,
								    bool affinity_tmr_update,
								    __u32 cookie)
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
	struct calico_nat_v4_affinity_key affkey = {
		.cookie = cookie,
	};
	__u64 now = 0;

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
	__u32 count = nat_lv1_val->count;

	if (from_tun) {
		count = nat_lv1_val->local;
	} else if (nat_lv1_val->flags & (NAT_FLG_INTERNAL_LOCAL | NAT_FLG_EXTERNAL_LOCAL)) {
		bool local_traffic = true;

		if (CALI_F_FROM_HEP) {
			struct cali_rt *rt = cali_rt_lookup(ip_src);

			if (!rt || (!cali_rt_is_host(rt) && !cali_rt_is_workload(rt))) {
				local_traffic = false;
			}
		}

		if ((local_traffic && (nat_lv1_val->flags & NAT_FLG_INTERNAL_LOCAL)) ||
				(!local_traffic && (nat_lv1_val->flags & NAT_FLG_EXTERNAL_LOCAL))) {
			count = nat_lv1_val->local;
			CALI_DEBUG("local_traffic %d count %d flags 0x%x\n", local_traffic, count, nat_lv1_val->flags);
		}
	}

	CALI_DEBUG("NAT: 1st level hit; id=%d\n", nat_lv1_val->id);

	if (count == 0) {
		CALI_DEBUG("NAT: no backend\n");
		*res = NAT_NO_BACKEND;
		return NULL;
	}

	if (nat_lv1_val->affinity_timeo == 0 && !affinity_always_timeo) {
		goto skip_affinity;
	}

	struct calico_nat_v4 nat_data = {
		.addr = ip_dst,
		.port = dport,
		.protocol = ip_proto,
	};
	affkey.nat_key = nat_data;
	affkey.client_ip = ip_src;

	CALI_DEBUG("NAT: backend affinity %d seconds\n", nat_lv1_val->affinity_timeo ? : affinity_always_timeo);

	struct calico_nat_v4_affinity_val *affval;

	now = bpf_ktime_get_ns();
	affval = cali_v4_nat_aff_lookup_elem(&affkey);
	if (affval) {
		int timeo = (affinity_always_timeo ? : nat_lv1_val->affinity_timeo);
		if (now - affval->ts <= timeo  * 1000000000ULL) {
			CALI_DEBUG("NAT: using affinity backend %x:%d\n",
					bpf_ntohl(affval->nat_dest.addr), affval->nat_dest.port);
			if (affinity_tmr_update) {
				affval->ts = now;
			}

			return &affval->nat_dest;
		}
		CALI_DEBUG("NAT: affinity expired for %x:%d\n", bpf_ntohl(ip_dst), dport);
	} else {
		CALI_DEBUG("no previous affinity for %x:%d", bpf_ntohl(ip_dst), dport);
	}
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

	if (nat_lv1_val->affinity_timeo != 0 || affinity_always_timeo) {
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

static CALI_BPF_INLINE struct calico_nat_dest* calico_v4_nat_lookup2(__be32 ip_src, __be32 ip_dst,
								    __u8 ip_proto, __u16 dport,
								    bool from_tun,
								    nat_lookup_result *res)
{
	return calico_v4_nat_lookup(ip_src, ip_dst, ip_proto, dport, from_tun, res, 0, false, 0);
}

#endif /* __CALI_NAT_LOOKUP_H__ */
