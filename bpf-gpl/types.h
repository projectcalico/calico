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

#ifndef __CALI_BPF_TYPES_H__
#define __CALI_BPF_TYPES_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include "bpf.h"
#include "arp.h"
#include "conntrack_types.h"
#include "nat_types.h"
#include "reasons.h"

// struct cali_tc_state holds state that is passed between the BPF programs.
// WARNING: must be kept in sync with the definitions in bpf/polprog/pol_prog_builder.go.
struct cali_tc_state {
	__be32 ip_src;
	__be32 ip_dst;
	__be32 post_nat_ip_dst;
	__be32 tun_ip;
	__s32 pol_rc;
	__u16 sport;
	union
	{
		__u16 dport;
		struct
		{
			__u8 icmp_type;
			__u8 icmp_code;
		};
	};
	__u16 post_nat_dport;
	__u8 ip_proto;
	__u8 flags;
	struct calico_ct_result ct_result;
	struct calico_nat_dest nat_dest;
	__u64 prog_start_time;
};

struct fwd {
	int res;
	__u32 mark;
	enum calico_reason reason;
#if CALI_FIB_ENABLED
	__u32 fib_flags;
	bool fib;
#endif
};

struct cali_tc_ctx {
  struct __sk_buff *skb;

  /* Our single copies of the data start/end pointers loaded from the skb. */
  union {
  	void *data_start;
  	struct ethhdr *eth; /* If there is an ethhdr it's at the start. */
  };
  void *data_end;

  struct cali_tc_state *state;

  struct iphdr *ip_header;
  union {
    void *nh;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
  };

  struct calico_nat_dest *nat_dest;
  struct arp_key arpk;
  struct fwd fwd;
};

#endif /* __CALI_BPF_TYPES_H__ */
