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

package cleanupv1

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	v4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

// Both our key and value are actually keys from the conntrack map.

const KeyV6Size = v4.KeyV6Size
const ValueV6Size = KeyV6Size + 8 + 8

type ValueV6 [ValueV6Size]byte

var MapParamsV6 = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeyV6Size,
	ValueSize:    ValueV6Size,
	MaxEntries:   MaxEntries,
	Name:         "cali_v6_ccq",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      2,
	UpdatedByBPF: false,
}

func (e ValueV6) AsBytes() []byte {
	return e[:]
}

func (e *ValueV6) SetKey(key []byte) {
	copy(e[0:KeyV6Size], key)
}

func (e *ValueV6) SetTS(ts uint64) {
	binary.LittleEndian.PutUint64(e[KeyV6Size:KeyV6Size+8], ts)
}

func (e *ValueV6) SetRevTS(ts uint64) {
	binary.LittleEndian.PutUint64(e[KeyV6Size+8:], ts)
}

func (e ValueV6) OtherNATKey() v4.KeyInterface {
	var ret v4.KeyV6

	l := len(v4.KeyV6{})
	copy(ret[:l], e[0:KeyV6Size])

	return ret
}

func (e ValueV6) Timestamp() uint64 {
	return binary.LittleEndian.Uint64(e[KeySize : KeySize+8])
}

func (e ValueV6) RevTimestamp() uint64 {
	return binary.LittleEndian.Uint64(e[KeySize+8:])
}

func NewValueV6(key []byte, ts, rev_ts uint64) ValueV6 {
	v := ValueV6{}
	v.SetKey(key)
	v.SetTS(ts)
	v.SetRevTS(rev_ts)
	return v
}

type MapMemV6 map[v4.KeyV6]ValueV6

// LoadMapMem loads ConntrackMap into memory
func LoadMapMemV6(m maps.Map) (MapMemV6, error) {
	ret := make(MapMemV6)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		ks := len(v4.KeyV6{})
		vs := len(ValueV6{})

		var key v4.KeyV6
		copy(key[:ks], k[:ks])

		var val ValueV6
		copy(val[:vs], v[:vs])

		ret[key] = val
		return maps.IterNone
	})

	return ret, err
}
