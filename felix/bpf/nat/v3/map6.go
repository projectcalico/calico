// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

//	struct calico_nat_v4_key {
//	   uint32_t prefixLen;
//	   uint32_t addr; // NBO
//	   uint16_t port; // HBO
//	   uint8_t protocol;
//	   uint32_t saddr;
//	   uint8_t pad;
//	};
const FrontendKeyV6Size = 40

//	struct calico_nat_v4_value {
//	   uint32_t id;
//	   uint32_t count;
//	   uint32_t local;
//	   uint32_t affinity_timeo;
//	   uint32_t flags;
//	};
const FrontendValueV6Size = 20

var FrontendMapV6Parameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    FrontendKeyV6Size,
	ValueSize:  FrontendValueV6Size,
	MaxEntries: 64 * 1024,
	Name:       "cali_v6_nat_fe",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    3,
}
