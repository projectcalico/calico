// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_GLOBALS_H__
#define __CALI_GLOBALS_H__

struct cali_tc_globals {
	__be32 host_ip;
	__be16 tunnel_mtu;
	__be16 vxlan_port;
	__be32 intf_ip;
	__be32 ext_to_svc_mark;
	__be16 psnat_start;
	__be16 psnat_len;
	__be32 flags;
};

enum cali_globals_flags {
	/* CALI_GLOBALS_IPV6_ENABLED is set when IPv6 is enabled by Felix */
	CALI_GLOBALS_IPV6_ENABLED = 0x00000001,
	/* CALI_GLOBALS_IPIP_NO_OUTER_HEADERS is set for kernels in which IPIP tunnels acts
	 * like other l3 devices, where only inner ip header is seen by bpf programs. This
	 * behaviour started in kernel 5.14. Before 5.14, bpf programs attached to IPIP
	 * tunnels saw ethernet, outer ip header, inner ip header and payload */
	CALI_GLOBALS_IPIP_NO_OUTER_HEADERS = 0x00000002,
};

struct cali_ctlb_globals {
	__be32 udp_not_seen_timeo;
};

#endif /* __CALI_GLOBALS_H__ */
