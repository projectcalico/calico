// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

#include "bpf.h"

struct protoport {
	__u16 proto;
	__u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, union ip4_bpf_lpm_trie_key);
    __type(value, __u32);
    __uint(max_entries, 10240);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} calico_prefilter_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct protoport);
    __type(value, __u32);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} calico_failsafe_ports SEC(".maps");
