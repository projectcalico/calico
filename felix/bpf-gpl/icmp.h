// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ICMP_H__
#define __CALI_ICMP_H__

#ifdef IPVER6
#include "icmp6.h"

static CALI_BPF_INLINE int icmp_reply(struct cali_tc_ctx *ctx, __u8 type, __u8 code, __be32 un)
{
	return icmp_v6_reply(ctx, type, code, un);
}

#else
#include "icmp4.h"

static CALI_BPF_INLINE int icmp_reply(struct cali_tc_ctx *ctx, __u8 type, __u8 code, __be32 un)
{
	return icmp_v4_reply(ctx, type, code, un);
}

#endif

#endif /* __CALI_ICMP_H__ */
