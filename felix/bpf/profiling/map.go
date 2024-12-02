// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package profiling

import (
	"encoding/binary"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	KeySize   = 8  // 2 x uint32
	ValueSize = 16 // 2 x uint64
)

var MapParameters = maps.MapParameters{
	Type:       "percpu_hash",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 20000,
	Name:       "cali_profiling",
	Version:    2,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParameters)
}

type Key struct {
	Ifindex int
	Kind    int
}

func KeyFromBytes(b []byte) Key {
	return Key{
		Ifindex: int(binary.LittleEndian.Uint32(b[0:4])),
		Kind:    int(binary.LittleEndian.Uint32(b[4:8])),
	}
}

type Value struct {
	Time    int
	Samples int
}

func ValueFromBytes(b []byte) Value {
	return Value{
		Time:    int(binary.LittleEndian.Uint64(b[0:8])),
		Samples: int(binary.LittleEndian.Uint64(b[8:16])),
	}
}
