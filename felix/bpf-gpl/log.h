// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_LOG_H__
#define __CALI_LOG_H__

#include "bpf.h"

#define CALI_LOG_LEVEL_OFF 0
#define CALI_LOG_LEVEL_INFO 5
#define CALI_LOG_LEVEL_DEBUG 10
#define CALI_LOG_LEVEL_VERB 20

#ifndef CALI_LOG_LEVEL
#define CALI_LOG_LEVEL CALI_LOG_LEVEL_OFF
#endif

#define CALI_USE_LINUX_FIB true

#ifdef IPVER6
#define IPVER_PFX	"IPv6 "
#else
#define IPVER_PFX	""
#endif

#ifdef BPF_CORE_SUPPORTED
#define bpf_log(__fmt, ...) do { \
		char fmt[] = IPVER_PFX __fmt; \
		bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
} while (0)
#else
#define bpf_log(__fmt, ...) do { \
		char fmt[] = IPVER_PFX __fmt "\n"; \
		bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
} while (0)
#endif /* BPF_CORE_SUPPORTED */

#ifndef CALI_LOG
#define CALI_LOG bpf_log
#endif

#define CALI_INFO_NO_FLAG(fmt, ...)  CALI_LOG_IF(CALI_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define CALI_DEBUG_NO_FLAG(fmt, ...) CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)

#define CALI_INFO(fmt, ...) \
	__CALI_LOG_IF(CALI_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define CALI_DEBUG(fmt, ...) \
	__CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define CALI_VERB(fmt, ...) \
	__CALI_LOG_IF(CALI_LOG_LEVEL_VERB, fmt, ## __VA_ARGS__)

#define __CALI_LOG_IF(level, fmt, ...) do { \
	if (CALI_LOG_LEVEL >= (level))    \
		CALI_LOG(fmt, ## __VA_ARGS__);          \
} while (0)

#define CALI_LOG_IF(level, fmt, ...) do { \
	if (CALI_LOG_LEVEL >= (level))    \
		bpf_log(fmt, ## __VA_ARGS__);          \
} while (0)

#define XSTR(S) STR(S)
#define STR(S) #S

#endif /* __CALI_LOG_H__ */
