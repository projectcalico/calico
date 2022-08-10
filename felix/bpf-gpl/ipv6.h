// Project Calico BPF dataplane programs.
// Copyright (c) 2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_IPV6_H__
#define __CALI_BPF_IPV6_H__

static CALI_BPF_INLINE void ipv6_log_addr(struct ipv6hdr *ipv6) {
	// We can only pass in 3 parameters to a helper function because of bpf architecture,
	// so we need to split printing ipv6 address into 2 parts.
	CALI_DEBUG("src: %x%x",
			bpf_ntohl(ipv6->saddr.in6_u.u6_addr32[0]),
			bpf_ntohl(ipv6->saddr.in6_u.u6_addr32[1]));
	CALI_DEBUG("%x%x\n",
			bpf_ntohl(ipv6->saddr.in6_u.u6_addr32[2]),
			bpf_ntohl(ipv6->saddr.in6_u.u6_addr32[3]));

	CALI_DEBUG("dst: %x%x",
			bpf_ntohl(ipv6->daddr.in6_u.u6_addr32[0]),
			bpf_ntohl(ipv6->daddr.in6_u.u6_addr32[1]));
	CALI_DEBUG("%x%x\n",
			bpf_ntohl(ipv6->daddr.in6_u.u6_addr32[2]),
			bpf_ntohl(ipv6->daddr.in6_u.u6_addr32[3]));
}

#endif  /* __CALI_BPF_IPV6_H__ */
