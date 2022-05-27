// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_IF_STATE_H__
#define __CALI_IF_STATE_H__

CALI_MAP(cali_iface, 2,
		BPF_MAP_TYPE_HASH,
		__u32, __u32,
		1000, BPF_F_NO_PREALLOC, MAP_PIN_GLOBAL)

#define IFACE_STATE_WEP		0x1
#define IFACE_STATE_READY	0x2

#define iface_is_worload(state)		((state) & IFACE_STATE_WEP)
#define iface_is_ready(state)		((state) & IFACE_STATE_READY)

#endif /* __CALI_IF_STATE_H__ */
