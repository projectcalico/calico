// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <iproute2/bpf_elf.h>

#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "counters.h"

const volatile struct cali_tc_globals __globals;

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb);

__attribute__((section("classifier/calico_unittest"))) int unittest(struct __sk_buff *skb)
{
	return calico_unittest_entry(skb);
}
