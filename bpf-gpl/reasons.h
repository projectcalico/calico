// Project Calico BPF dataplane programs.
// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __CALI_REASONS_H__
#define __CALI_REASONS_H__

enum calico_reason {
	CALI_REASON_UNKNOWN = 0x00,
	CALI_REASON_SHORT = 0x01,
	CALI_REASON_NOT_IP = 0xea,
	CALI_REASON_V6_WORKLOAD = 0x06,
	CALI_REASON_FAILSAFE = 0xfa,
	CALI_REASON_DNT = 0xd0,
	CALI_REASON_PREDNAT = 0xd1,
	CALI_REASON_POL = 0xbe,
	CALI_REASON_CT = 0xc0,
	CALI_REASON_BYPASS = 0xbb,
	CALI_REASON_CT_NAT = 0xc1,
	CALI_REASON_CSUM_FAIL= 0xcf,
	CALI_REASON_ENCAP_FAIL = 0xef,
	CALI_REASON_DECAP_FAIL = 0xdf,
	CALI_REASON_ICMP_DF = 0x1c,
	CALI_REASON_IP_OPTIONS = 0xeb,
	CALI_REASON_IP_MALFORMED = 0xec,
	CALI_REASON_UNAUTH_SOURCE = 0xed,
	CALI_REASON_RT_UNKNOWN = 0xdead,
};

#endif /* __CALI_REASONS_H__ */
