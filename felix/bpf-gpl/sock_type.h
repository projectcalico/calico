// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_SOCK_TYPE_H__
#define __CALI_SOCK_TYPE_H__

/* Socket types for the cgroup socket programs.  The libc definitions live in
 * sys/socket.h, which BPF builds cannot include, so define the (ABI-fixed)
 * values here.
 */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

#endif /* __CALI_SOCK_TYPE_H__ */
