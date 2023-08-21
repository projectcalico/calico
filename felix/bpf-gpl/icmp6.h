// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ICMP6_H__
#define __CALI_ICMP6_H__

static CALI_BPF_INLINE bool icmp_type_is_err(__u8 type) {
	return false;
}

#endif /* __CALI_ICMP6_H__ */
