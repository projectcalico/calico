//go:build !windows
// +build !windows

// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package polprog

import (
	"encoding/binary"

	"github.com/projectcalico/calico/felix/bpf"
)

const keySize = 8
const valueSize = 8

var RuleCounterParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_rule_ctrs",
	Type:       "percpu_hash",
	KeySize:    keySize,
	ValueSize:  valueSize,
	MaxEntries: 10000,
	Name:       "cali_rule_ctrs",
	Version:    2,
}

func RuleCountersMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(RuleCounterParameters)
}

type RuleCounterMapMem map[uint64]uint64

func LoadMap(m bpf.Map) (RuleCounterMapMem, error) {
	ret := make(RuleCounterMapMem)

	if err := m.Open(); err != nil {
		return nil, err
	}

	err := m.Iter(MapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// MapMemIter returns bpf.MapIter that loads the provided RuleCounterMapMem
func MapMemIter(m RuleCounterMapMem) bpf.IterCallback {
	return func(k, v []byte) bpf.IteratorAction {
		var value uint64
		key := binary.LittleEndian.Uint64(k)
		for i := 0; i < bpf.NumPossibleCPUs(); i++ {
			start := i * valueSize
			val := binary.LittleEndian.Uint64(v[start : start+valueSize])
			value = value + val
		}
		m[key] = value
		return bpf.IterNone
	}
}
