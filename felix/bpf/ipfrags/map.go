// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package ipfrags

import (
	"github.com/projectcalico/calico/felix/bpf/maps"
)

func init() {
	maps.SetSize(MapParams.VersionedName(), MapParams.MaxEntries)
}

var MapParams = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 10000, // max number of nodes that can forward nodeports to a single node
	Name:       "cali_v4_frags",
	Version:    2,
}

const (
	KeySize   = 12
	ValueSize = 2 + 2 + 4 + 1504
)

func Map() maps.Map {
	return maps.NewPinnedMap(MapParams)
}

var MapParameters = maps.MapParameters{
	Type:       "percpu_array",
	KeySize:    4,
	ValueSize:  ValueSize,
	MaxEntries: 1,
	Name:       "cali_v4_frgtmp",
	Version:    2,
}

func MapTmp() maps.Map {
	return maps.NewPinnedMap(MapParameters)
}
