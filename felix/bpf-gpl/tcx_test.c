// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tcx/ingress")
int cali_tcx_test(struct __sk_buff *skb)
{
	return -1;
}

char _license[] SEC("license") = "GPL";
