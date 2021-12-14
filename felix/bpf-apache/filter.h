// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>
#include "bpf.h"

struct protoport {
	__u16 proto;
	__u16 port;
};

struct bpf_map_def __attribute__((section("maps"))) calico_prefilter_v4 = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = sizeof(union ip4_bpf_lpm_trie_key),
	.value_size     = sizeof(__u32),
	.max_entries    = 10240,
	.map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def __attribute__((section("maps"))) calico_failsafe_ports = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct protoport),
	.value_size     = 1,
	.max_entries    = 65535,
	.map_flags      = BPF_F_NO_PREALLOC,
};
