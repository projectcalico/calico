#ifndef __CALICO_LOG_H__
#define __CALICO_LOG_H__

#define CALICO_LOG_LEVEL_OFF 0
#define CALICO_LOG_LEVEL_INFO 5
#define CALICO_LOG_LEVEL_DEBUG 10

#ifndef CALICO_LOG_LEVEL
#define CALICO_LOG_LEVEL CALICO_LOG_LEVEL_OFF
#endif

#define CALICO_USE_LINUX_FIB true

#define LOG(__fmt, ...) do { \
		char fmt[] = __fmt; \
		bpf_trace_printk(fmt, sizeof(fmt), ## __VA_ARGS__); \
} while (0)

#define CALICO_INFO(fmt, ...)  LOG_LEVEL(CALICO_LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define CALICO_DEBUG(fmt, ...) LOG_LEVEL(CALICO_LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)

#define CALICO_INFO_AT(fmt, ...) \
	LOG_LEVEL_FLG(CALICO_LOG_LEVEL_INFO, flags, fmt, ## __VA_ARGS__)
#define CALICO_DEBUG_AT(fmt, ...) \
	LOG_LEVEL_FLG(CALICO_LOG_LEVEL_DEBUG, flags, fmt, ## __VA_ARGS__)

#define LOG_LEVEL(level, fmt, ...) do { \
	if (CALICO_LOG_LEVEL >= (level))    \
		LOG(fmt, ## __VA_ARGS__);          \
} while (0)

#define LOG_LEVEL_FLG(level, flags, fmt, ...) do { \
	if (CALICO_LOG_LEVEL >= (level))    \
		LOG_FLG(flags, fmt, ## __VA_ARGS__);          \
} while (0)

#define LOG_FLG(flags, fmt, ...) do { \
	if (((flags) & CALICO_TC_HOST_EP) && ((flags) & CALICO_TC_INGRESS)) { \
		LOG("HI: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALICO_TC_HOST_EP) { \
		LOG("HE: " fmt, ## __VA_ARGS__); \
	} else if ((flags) & CALICO_TC_INGRESS) { \
		LOG("WI: " fmt, ## __VA_ARGS__); \
	} else { \
		LOG("WE: " fmt, ## __VA_ARGS__); \
	} \
} while (0)

#endif /* __CALICO_LOG_H__ */
