// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

#ifndef __CALI_BPF_TC_H__
#define __CALI_BPF_TC_H__

#include "types.h"

static CALI_BPF_INLINE int calico_tc(struct __sk_buff *skb);

static CALI_BPF_INLINE struct fwd calico_tc_skb_accepted(struct cali_tc_ctx *ctx,
							 struct calico_nat_dest *nat_dest);

int parse_packet(struct __sk_buff *skb, struct cali_tc_ctx *ctx);

#endif /* __CALI_BPF_TC_H__ */
