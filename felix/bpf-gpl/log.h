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

#define CALI_USE_LINUX_FIB true

#ifdef IPVER6
#define IPVER_PFX	"IPv6 "
#else
#define IPVER_PFX	""
#endif

#define CALI_LOG(__fmt, ...) do { \
		char fmt[] = IPVER_PFX __fmt; \
		bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
} while (0)

#if !(CALI_F_XDP) && !(CALI_F_CGROUP)
#define CALI_IFACE_LOG(fmt, ...) CALI_LOG("%s" fmt, ctx->globals->data.iface_name, ## __VA_ARGS__)
#elif CALI_F_XDP
#define CALI_IFACE_LOG(fmt, ...) CALI_LOG("%s" fmt, ctx->xdp_globals->iface_name, ## __VA_ARGS__)
#else
#define CALI_IFACE_LOG(fmt, ...) /* just for cases like ctlb whenit is not used */
#endif

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
		CALI_LOG("CTLB------------: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALI_XDP_PROG) { \
		CALI_IFACE_LOG("-X: " fmt, ## __VA_ARGS__); \
	} else if (((flags) & CALI_TC_HOST_EP) && ((flags) & CALI_TC_INGRESS)) { \
		CALI_IFACE_LOG("-I: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALI_TC_HOST_EP) { \
		CALI_IFACE_LOG("-E: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALI_TC_INGRESS) { \
		CALI_IFACE_LOG("-I: " fmt, ## __VA_ARGS__); \
	} else { \
		CALI_IFACE_LOG("-E: " fmt, ## __VA_ARGS__); \
	} \
} while (0)

#define XSTR(S) STR(S)
#define STR(S) #S

#endif /* __CALI_LOG_H__ */
