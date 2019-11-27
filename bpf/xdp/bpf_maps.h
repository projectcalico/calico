#ifndef __CALI_BPF_MAPS_H__
#define __CALI_BPF_MAPS_H__

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include "../include/bpf.h"
#include "../include/conntrack.h"

struct protoport {
	__u16 proto;
	__u16 port;
};

enum calico_reason {
	CALI_REASON_UNKNOWN = 0x00,
	CALI_REASON_SHORT = 0x01,
	CALI_REASON_NOT_IP = 0xea,
	CALI_REASON_FAILSAFE = 0xfa,
	CALI_REASON_DNT = 0xd0,
	CALI_REASON_PREDNAT = 0xd1,
	CALI_REASON_POL = 0xbe,
	CALI_REASON_CT = 0xc0,
	CALI_REASON_BYPASS = 0xbb,
	CALI_REASON_CT_NAT = 0xc1,
	CALI_REASON_CSUM_FAIL= 0xcf,
};

#endif /* __CALI_BPF_MAPS_H__ */
