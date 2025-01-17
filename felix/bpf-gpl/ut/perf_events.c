// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include "ut.h"
#include "bpf.h"
#include "perf.h"
#include "skb.h"

#include <linux/ip.h>
#include <linux/udp.h>

struct tuple {
	struct perf_event_header hdr;
	__u32 ip_src;
	__u32 ip_dst;
	__u16 port_src;
	__u16 port_dst;
	__u8 proto;
	__u8 _pad[1027];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct tuple);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
}cali_perf_scratch SEC(".maps");

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb)
{
	int err;
	struct cali_tc_ctx _ctx = {
		.skb = skb,
		.ipheader_len = IP_SIZE,
	};
	struct cali_tc_ctx *ctx = &_ctx;

	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		ctx->fwd.reason = CALI_REASON_SHORT;
		CALI_DEBUG("Too short\n");
		return -1;
	}
	struct iphdr *ip = ctx->ip_header;

	int scratch_zero = 0;
	struct tuple *tp = bpf_map_lookup_elem(&cali_perf_scratch, &scratch_zero);

	if (!tp) {
		return -1;
	}
	tp->hdr.type = 0xdead,
	tp->hdr.len = sizeof(struct tuple),
	tp->ip_src = bpf_ntohl(ip->saddr);
	tp->ip_dst = bpf_ntohl(ip->daddr);
	tp->proto = ip->protocol;

	switch (ip->protocol) {
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (void*)(ip + 1);
			tp->port_src = bpf_ntohs(tcp->source);
			tp->port_dst = bpf_ntohs(tcp->dest);
		}
		break;
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (void*)(ip + 1);
			tp->port_src = bpf_ntohs(udp->source);
			tp->port_dst = bpf_ntohs(udp->dest);
		}
		break;
	}

	if (ip->protocol == IPPROTO_ICMP) {
		tp->hdr.type++;
		tp->hdr.len += skb->len;
		err = perf_commit_event_ctx(skb, skb->len, tp, sizeof(struct tuple));
	} else {
		err = perf_commit_event(skb, tp, sizeof(struct tuple));
	}
	CALI_DEBUG("perf_commit_event returns %d\n", err);

	return err == 0 ? TC_ACT_UNSPEC : TC_ACT_SHOT;
}
