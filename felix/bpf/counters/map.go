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

package counters

import "github.com/projectcalico/calico/felix/bpf"

var MapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_counters",
	Type:       "percpu_array",
	KeySize:    4, //__u32
	ValueSize:  uint32Size * MaxCounterNumber,
	MaxEntries: 1,
	Name:       bpf.CountersMapName(),
}

func Map(mc *bpf.MapContext, pinPath string) bpf.Map {
	MapParameters.Filename = pinPath
	return mc.NewPinnedMap(MapParameters)
}
