// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_SOCK_TYPE_H__
#define __CALI_SOCK_TYPE_H__

/* SOCK_STREAM/SOCK_DGRAM for the cgroup socket programs.  They live in
 * bits/socket_type.h, which refuses to be included except via sys/socket.h,
 * and sys/socket.h needs libc types that BPF builds lack.  Pretend
 * sys/socket.h is already included.
 */
#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H
#endif
#include <bits/socket_type.h>

#endif /* __CALI_SOCK_TYPE_H__ */
