// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_BPF_INLINE_H__
#define __CALI_BPF_INLINE_H__

/* Kept apart from bpf.h so that the headers shared with userspace (globals.h,
 * ip_addr.h) can use it without pulling in the BPF helper definitions.
 */
#define CALI_BPF_INLINE inline __attribute__((always_inline))

#define __unused __attribute__((unused))

#endif /* __CALI_BPF_INLINE_H__ */
