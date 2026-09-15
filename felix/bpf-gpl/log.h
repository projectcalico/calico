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

/* The no_trace_printk guard lets Felix strip every bpf_trace_printk reference
 * from a program at load time (see struct prog_flags): the flag lives in
 * frozen .rodata, so the verifier folds it and dead-code-eliminates the call.
 * When the flag is clear (the normal case) the condition folds to always-true,
 * so there is no runtime cost. */
#define bpf_log(__fmt, ...) do { \
		if (!PROG_FLAGS.no_trace_printk) { \
			__attribute__((section(".rodata.cali_debug"))) static const char fmt[] = IPVER_PFX __fmt; \
			bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
		} \
} while (0)

#ifndef CALI_LOG
#ifdef CALI_NO_TRACE_PRINTK
// Programs built with CALI_NO_TRACE_PRINTK must not reference the
// bpf_trace_printk helper at all: on a kernel with lockdown=confidentiality
// ftrace is disabled at boot, so loading any program that references the
// helper makes the kernel emit "could not enable bpf_trace_printk events" on
// every load. Compile the default log macro out entirely for those builds.
#define CALI_LOG(fmt, ...) do {} while (0)
#else
#define CALI_LOG bpf_log
#endif
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
