// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_GLOBALS_H__
#define __CALI_GLOBALS_H__

#include "ip_addr.h"

#define DECLARE_TC_GLOBAL_DATA(name, ip_t)	\
struct name {				\
	ip_t host_ip;			\
	__be16 tunnel_mtu;		\
	__be16 vxlan_port;		\
	ip_t intf_ip;			\
	__be32 ext_to_svc_mark;		\
	__be16 psnat_start;		\
	__be16 psnat_len;		\
	ip_t host_tunnel_ip;		\
	__be32 flags;			\
	__be16 wg_port;			\
	__be16 profiling;		\
	__u32 natin_idx;		\
	__u32 natout_idx;		\
	__u32 overlay_tunnel_id;	\
	__u8 iface_name[16];		\
	__u32 log_filter_jmp;		\
	__u32 jumps[40];		\
}

DECLARE_TC_GLOBAL_DATA(cali_tc_global_data, ipv6_addr_t);
struct cali_tc_globals {
	struct cali_tc_global_data data;

	/* Needs to be 32bit aligned as it is followed by scratch area for 				\
	 * building headers. We reuse the same slot in state map to save 				\
	 * ourselves a lookup. 										\
	 */												\
	__u32 __scratch[]; /* N.B. this provides pointer to the location but does not add to the size */ \
};

struct cali_tc_preamble_globals {
	struct cali_tc_global_data v4;
	struct cali_tc_global_data v6;
};

enum cali_globals_flags {
	CALI_GLOBALS_RESERVED1                 = 0x00000002,
	CALI_GLOBALS_RESERVED2                 = 0x00000004,
	CALI_GLOBALS_RESERVED3                 = 0x00000008,
	CALI_GLOBALS_RPF_OPTION_ENABLED        = 0x00000010,
	CALI_GLOBALS_RPF_OPTION_STRICT         = 0x00000020,
	CALI_GLOBALS_RESERVED7                 = 0x00000040,
	CALI_GLOBALS_NO_DSR_CIDRS              = 0x00000080,
	CALI_GLOBALS_LO_UDP_ONLY               = 0x00000100,
	CALI_GLOBALS_RESERVED10                = 0x00000200,
	CALI_GLOBALS_REDIRECT_PEER             = 0x00000400,
	CALI_GLOBALS_FLOWLOGS_ENABLED          = 0x00000800,
	CALI_GLOBALS_NATOUTGOING_EXCLUDE_HOSTS = 0x00001000,
	CALI_GLOBALS_SKIP_EGRESS_REDIRECT      = 0x00002000,
};

struct cali_ctlb_globals {
	__be32 udp_not_seen_timeo;
	bool exclude_udp;
};

struct cali_xdp_globals {
	__u8 iface_name[16];
	__u32 jumps[16];
};

struct cali_xdp_preamble_globals {
	struct cali_xdp_globals v4;
	struct cali_xdp_globals v6;
};

struct cali_ct_cleanup_globals {
    __u64 creation_grace;

    __u64 tcp_syn_sent;
    __u64 tcp_established;
    __u64 tcp_fins_seen;
    __u64 tcp_reset_seen;

    __u64 udp_timeout;

    __u64 generic_timeout;

    __u64 icmp_timeout;
};

#endif /* __CALI_GLOBALS_H__ */
