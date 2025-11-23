// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_CTLB_MAPS_H__
#define __CALI_CTLB_MAPS_H__

#include <linux/bpf.h>
#include <stdbool.h>
#include "bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
}cali_ctlb_conn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
}cali_ctlb_send SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
}cali_ctlb_recv SEC(".maps");

#endif
