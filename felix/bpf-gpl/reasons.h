// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_REASONS_H__
#define __CALI_REASONS_H__

// The following values are used as index to counters map, and should be kept in sync
// with constants defined in bpf/counters/counters.go
enum calico_reason {
	CALI_REASON_UNKNOWN,
	COUNTER_TOTAL_PACKETS = CALI_REASON_UNKNOWN,
	CALI_REASON_ACCEPTED_BY_FAILSAFE,
	CALI_REASON_ACCEPTED_BY_POLICY,
	CALI_REASON_BYPASS,
	CALI_REASON_DROPPED_BY_POLICY,
	CALI_REASON_SHORT,
	CALI_REASON_CSUM_FAIL,
	CALI_REASON_IP_OPTIONS,
	CALI_REASON_IP_MALFORMED,
	CALI_REASON_ENCAP_FAIL,
	CALI_REASON_DECAP_FAIL,
	CALI_REASON_UNAUTH_SOURCE,
	CALI_REASON_RT_UNKNOWN,
	CALI_REASON_ACCEPTED_BY_XDP, // Not used by countres map
	CALI_REASON_WEP_NOT_READY,
};

#define DENY_REASON(ctx, res) 	\
	(ctx)->fwd.reason = res; 	\
	COUNTER_INC(ctx, res);

#endif /* __CALI_REASONS_H__ */
