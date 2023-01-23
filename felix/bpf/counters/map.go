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

import (
	"encoding/binary"

	"github.com/projectcalico/calico/felix/bpf"
)

const PolicyMapKeySize = 8
const PolicyMapValueSize = 8

var MapParameters = bpf.MapParameters{
	Type:       "percpu_hash",
	KeySize:    counterMapKeySize,
	ValueSize:  counterMapValueSize * MaxCounterNumber,
	MaxEntries: 20000,
	Name:       "cali_counters",
	Version:    2,
}

func Map() bpf.Map {
	return bpf.NewPinnedMap(MapParameters)
}

var PolicyMapParameters = bpf.MapParameters{
	Type:       "percpu_hash",
	KeySize:    PolicyMapKeySize,
	ValueSize:  PolicyMapValueSize,
	MaxEntries: 10000,
	Name:       "cali_rule_ctrs",
	Version:    2,
}

func PolicyMap() bpf.Map {
	return bpf.NewPinnedMap(PolicyMapParameters)
}

type PolicyMapMem map[uint64]uint64

func LoadPolicyMap(m bpf.Map) (PolicyMapMem, error) {
	ret := make(PolicyMapMem)

	if err := m.Open(); err != nil {
		return nil, err
	}

	err := m.Iter(PolicyMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// PolicyMapMemIter returns bpf.MapIter that loads the provided PolicyMapMem
func PolicyMapMemIter(m PolicyMapMem) bpf.IterCallback {
	return func(k, v []byte) bpf.IteratorAction {
		var value uint64
		key := binary.LittleEndian.Uint64(k)
		for i := 0; i < bpf.NumPossibleCPUs(); i++ {
			start := i * PolicyMapValueSize
			val := binary.LittleEndian.Uint64(v[start : start+PolicyMapValueSize])
			value = value + val
		}
		m[key] = value
		return bpf.IterNone
	}
}
