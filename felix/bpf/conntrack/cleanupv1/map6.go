// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
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

package v3

import (
	"golang.org/x/sys/unix"

	v3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

// Both our key and value are actually keys from the conntrack map.

const KeyV6Size = v3.KeyV6Size
const ValueV6Size = KeyV6Size

type KeyV6 = v3.KeyV6
type ValueV6 = v3.KeyV6

var MapParamsV6 = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeyV6Size,
	ValueSize:    ValueV6Size,
	MaxEntries:   MaxEntries,
	Name:         "cali_v6_ccq",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      1,
	UpdatedByBPF: true,
}
