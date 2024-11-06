// Project Calico BPF dataplane programs.
// Copyright (c) 2024 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_CT_CLEAN_H__
#define __CALI_CT_CLEAN_H__

#include "bpf.h"
#include "types.h"
#include "counters.h"
#include "conntrack.h"
#include "conntrack_types.h"

#ifdef IPVER6
#define CCQ_MAP cali_v6_ccq
#define CCQ_MAP_V cali_v6_ccq1
#define CT_MAP_V cali_v6_ct3
#else
#define CCQ_MAP cali_v4_ccq
#define CCQ_MAP_V cali_v4_ccq1
#define CT_MAP_V cali_v4_ct3
#endif

// The cali_ccq map is our "cleanup queue".  NAT records in the conntrack map
// require two entries in the map, a forward entry and a reverse entry. When
// deleting a NAT entry pair, we want to delete both entries together with
// as little time between as possible in order to avoid racing with the
// dataplane.  To do that, we copy the keys to this map temporarily and then
// iterate over this map, deleting the pair together.
CALI_MAP_NAMED(CCQ_MAP, cali_ccq, 1,
		BPF_MAP_TYPE_HASH,
		struct calico_ct_key, // key = NAT rev key
		struct calico_ct_key, // value = NAT fwd key
		100000,
		BPF_F_NO_PREALLOC
);

#endif // __CALI_CT_CLEAN_H__
