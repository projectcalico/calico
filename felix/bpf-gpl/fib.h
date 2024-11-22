// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_FIB_H__
#define __CALI_FIB_H__

#include "fib_common.h"
#ifdef BPF_CORE_SUPPORTED
#include "fib_co_re.h"
#else
#include "fib_legacy.h"
#endif

#endif /* __CALI_FIB_H__ */
