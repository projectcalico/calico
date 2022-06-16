// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_REASONS_H__
#define __CALI_REASONS_H__

enum calico_reason {
	CALI_REASON_UNKNOWN,
	CALI_REASON_SHORT,
	CALI_REASON_CSUM_FAIL,
	CALI_REASON_ACCEPTED_BY_FAILSAFE,
	CALI_REASON_ACCEPTED_BY_POLICY,
	CALI_REASON_DROPPED_BY_POLICY,
	// All above values are also used as index to counters map entry
	CALI_REASON_BYPASS = 0xbb,
	CALI_REASON_ENCAP_FAIL = 0xef,
	CALI_REASON_DECAP_FAIL = 0xdf,
	CALI_REASON_IP_OPTIONS = 0xeb,
	CALI_REASON_IP_MALFORMED = 0xec,
	CALI_REASON_UNAUTH_SOURCE = 0xed,
	CALI_REASON_RT_UNKNOWN = 0xdead,
	CALI_REASON_ACCEPTED_BY_XDP = 0xd9,
};

#define DENY_REASON(ctx, res) 	\
	(ctx)->fwd.reason = res; 	\
	INC(ctx, res);

#endif /* __CALI_REASONS_H__ */
