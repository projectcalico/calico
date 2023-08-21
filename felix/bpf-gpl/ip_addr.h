// Project Calico BPF dataplane programs.
// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_IP_ADDR_H__
#define __CALI_IP_ADDR_H__

typedef struct {
	__be32 a;
	__be32 b;
	__be32 c;
	__be32 d;
} ipv6_addr_t;

typedef __be32 ipv4_addr_t;

#ifdef IPVER6

#include <linux/in6.h>

static CALI_BPF_INLINE bool ipv6_addr_t_eq(ipv6_addr_t x, ipv6_addr_t y)
{
	return x.a == y.a && x.b == y.b && x.c == y.c && x.d == y.d;
}

static CALI_BPF_INLINE int ipv6_addr_t_cmp(ipv6_addr_t x, ipv6_addr_t y)
{
	if (x.a < y.a) {
		return -1;
	} else if (x.a == y.a) {
		if (x.b < y.b) {
			return -1;
		} else if (x.b == y.b) {
			if (x.c < y.c) {
				return -1;
			} else if (x.c == y.c) {
				if (x.d < y.d) {
					return -1;
				} else if (x.d == y.d) {
					return 0;
				}
			}
		}
	}

	return 1;
}

#define ip_void(ip)	((ip).a == 0 && (ip).b == 0 && (ip).c == 0 && (ip).d == 0)
#define VOID_IP		({ipv6_addr_t x = {}; x;})
#define ip_set_void(ip)	do {	\
	(ip).a = 0;		\
	(ip).b = 0;		\
	(ip).c = 0;		\
	(ip).d = 0;		\
} while(0)
#define NP_SPECIAL_IP	({ipv6_addr_t x = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff }; x;})
#define ip_equal(a, b)	ipv6_addr_t_eq(a, b)
#define ip_lt(a, b)	(ipv6_addr_t_cmp(a, b) < 0)

static CALI_BPF_INLINE void ipv6hdr_ip_to_ipv6_addr_t(ipv6_addr_t *us, struct in6_addr *lnx)
{
	us->a = lnx->in6_u.u6_addr32[0];
	us->b = lnx->in6_u.u6_addr32[1];
	us->c = lnx->in6_u.u6_addr32[2];
	us->d = lnx->in6_u.u6_addr32[3];
}

static CALI_BPF_INLINE void ipv6_addr_t_to_ipv6hdr_ip(struct in6_addr *lnx, ipv6_addr_t *us)
{
	lnx->in6_u.u6_addr32[0] = us->a;
	lnx->in6_u.u6_addr32[1] = us->b;
	lnx->in6_u.u6_addr32[2] = us->c;
	lnx->in6_u.u6_addr32[3] = us->d;
}

typedef ipv6_addr_t ipv46_addr_t;

#define DECLARE_IP_ADDR(name)	ipv6_addr_t name
#else

#define ip_void(ip)	((ip) == 0)
#define VOID_IP		0
#define ip_set_void(ip)	((ip) = 0)
#define NP_SPECIAL_IP	0xffffffff
#define ip_equal(a, b)	((a) == (b))
#define ip_lt(a, b)	((a) < (b))

typedef ipv4_addr_t ipv46_addr_t;

#define DECLARE_IP_ADDR(name)	union {					\
					ipv4_addr_t name;		\
					ipv6_addr_t __pad ## name;	\
				}
#endif

#endif /* __CALI_IP_ADDR_H__ */
