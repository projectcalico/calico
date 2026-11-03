// Project Calico BPF dataplane programs.
// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_PARSING_TYPES_H__
#define __CALI_PARSING_TYPES_H__

/* Results of parse_packet_ip(), shared by parsing.h and the per-IP-version
 * implementations in parsing4.h and parsing6.h.
 */
#define PARSING_OK 0
#define PARSING_OK_V6 1
#define PARSING_ALLOW_WITHOUT_ENFORCING_POLICY 2
#define PARSING_FRAG_STORED 3
#define PARSING_ERROR -1

#endif /* __CALI_PARSING_TYPES_H__ */
