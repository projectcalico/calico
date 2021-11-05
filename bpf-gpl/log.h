// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_LOG_H__
#define __CALI_LOG_H__

#define CALI_LOG_LEVEL_OFF 0
#define CALI_LOG_LEVEL_INFO 5
#define CALI_LOG_LEVEL_DEBUG 10
#define CALI_LOG_LEVEL_VERB 20

#ifndef CALI_LOG_LEVEL
#define CALI_LOG_LEVEL CALI_LOG_LEVEL_OFF
#endif

#ifndef CALI_LOG_PFX
#define CALI_LOG_PFX CALI
#endif

#define CALI_USE_LINUX_FIB true

#define CALI_LOG(__fmt, ...) do { \
		char fmt[] = __fmt; \
		bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
} while (0)

#define CALI_INFO_NO_FLAG(fmt, ...)  CALI_LOG_IF(CALI_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define CALI_DEBUG_NO_FLAG(fmt, ...) CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)

#define CALI_INFO(fmt, ...) \
	CALI_LOG_IF_FLAG(CALI_LOG_LEVEL_INFO, CALI_COMPILE_FLAGS, fmt, ## __VA_ARGS__)
#define CALI_DEBUG(fmt, ...) \
	CALI_LOG_IF_FLAG(CALI_LOG_LEVEL_DEBUG, CALI_COMPILE_FLAGS, fmt, ## __VA_ARGS__)
#define CALI_VERB(fmt, ...) \
	CALI_LOG_IF_FLAG(CALI_LOG_LEVEL_VERB, CALI_COMPILE_FLAGS, fmt, ## __VA_ARGS__)

#define CALI_LOG_IF(level, fmt, ...) do { \
	if (CALI_LOG_LEVEL >= (level))    \
		CALI_LOG(fmt, ## __VA_ARGS__);          \
} while (0)

#define CALI_LOG_IF_FLAG(level, flags, fmt, ...) do { \
	if (CALI_LOG_LEVEL >= (level))    \
		CALI_LOG_FLAG(flags, fmt, ## __VA_ARGS__);          \
} while (0)

#define CALI_LOG_FLAG(flags, fmt, ...) do { \
	if ((flags) & CALI_CGROUP) { \
		CALI_LOG(XSTR(CALI_LOG_PFX) "-C: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALI_XDP_PROG) { \
		CALI_LOG(XSTR(CALI_LOG_PFX) "-X: " fmt, ## __VA_ARGS__); \
	} else if (((flags) & CALI_TC_HOST_EP) && ((flags) & CALI_TC_INGRESS)) { \
		CALI_LOG(XSTR(CALI_LOG_PFX) "-I: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALI_TC_HOST_EP) { \
		CALI_LOG(XSTR(CALI_LOG_PFX) "-E: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALI_TC_INGRESS) { \
		CALI_LOG(XSTR(CALI_LOG_PFX) "-I: " fmt, ## __VA_ARGS__); \
	} else { \
		CALI_LOG(XSTR(CALI_LOG_PFX) "-E: " fmt, ## __VA_ARGS__); \
	} \
} while (0)

#define XSTR(S) STR(S)
#define STR(S) #S

#endif /* __CALI_LOG_H__ */
