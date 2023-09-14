// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_ICMP_H__
#define __CALI_ICMP_H__

#ifdef IPVER6
#include "icmp6.h"
#else
#include "icmp4.h"
#endif

#endif /* __CALI_ICMP_H__ */
