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

#include "bpf.h"

#define ENVOY_IP 0x100007f
#define ENVOY_PORT 0x993a

struct sock_key {
	__u32 ip4;
	__u32 port;
	__u32 envoy_side;
};

struct bpf_map_def __attribute__((section("maps"))) calico_sock_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(__u32),
	.max_entries    = 65535,
};
