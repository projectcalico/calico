// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_TC_H__
#define __CALI_BPF_TC_H__

#include "types.h"

static CALI_BPF_INLINE int calico_tc(struct __sk_buff *skb);

static CALI_BPF_INLINE struct fwd calico_tc_skb_accepted(struct cali_tc_ctx *ctx,
							 struct calico_nat_dest *nat_dest);

static CALI_BPF_INLINE int pre_policy_processing(struct cali_tc_ctx *ctx);
static CALI_BPF_INLINE void calico_tc_process_ct_lookup(struct cali_tc_ctx *ctx);

int parse_packet(struct __sk_buff *skb, struct cali_tc_ctx *ctx);

#endif /* __CALI_BPF_TC_H__ */
