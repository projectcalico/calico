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
	__be32 host_tunnel_ip;
	__be32 flags;
	__be16 wg_port;
	__be16 __pad;
	__u32 natin_idx;
	__u32 natout_idx;
	__u8 iface_name[16];
	__u32 log_filter_jmp;
	__u32 jumps[32];
	/* Needs to be 32bit aligned as it is followed by scratch area for
	 * building headers. We reuse the same slot in state map to save
	 * ourselves a lookup.
	 */
	__u32 __scratch[]; /* N.B. this provides pointer to the location but does not add to the size */
};

enum cali_globals_flags {
	/* CALI_GLOBALS_IPV6_ENABLED is set when IPv6 is enabled by Felix */
	CALI_GLOBALS_IPV6_ENABLED		= 0x00000001,
	CALI_GLOBALS_RESERVED1			= 0x00000002,
	CALI_GLOBALS_RESERVED2			= 0x00000004,
	CALI_GLOBALS_RESERVED3			= 0x00000008,
	CALI_GLOBALS_RPF_OPTION_ENABLED		= 0x00000010,
	CALI_GLOBALS_RPF_OPTION_STRICT		= 0x00000020,
	CALI_GLOBALS_RESERVED7			= 0x00000040,
	CALI_GLOBALS_NO_DSR_CIDRS		= 0x00000080,
};

struct cali_ctlb_globals {
	__be32 udp_not_seen_timeo;
	bool exclude_udp;
};

struct cali_xdp_globals {
	__u8 iface_name[16];
	__u32 jumps[16];
};

#endif /* __CALI_GLOBALS_H__ */
