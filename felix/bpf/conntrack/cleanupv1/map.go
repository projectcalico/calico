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

const KeySize = v4.KeySize
const ValueSize = KeySize + 8 + 8
const MaxEntries = 100000

type Value [ValueSize]byte

var MapParams = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_v4_ccq",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      2,
	UpdatedByBPF: false,
}

func (e Value) AsBytes() []byte {
	return e[:]
}

func (e *Value) SetKey(key []byte) {
	copy(e[0:KeySize], key)
}

func (e *Value) SetTS(ts uint64) {
	binary.LittleEndian.PutUint64(e[KeySize:KeySize+8], ts)
}

func (e *Value) SetRevTS(ts uint64) {
	binary.LittleEndian.PutUint64(e[KeySize+8:], ts)
}

func (e Value) OtherNATKey() v4.KeyInterface {
	var ret v4.Key

	l := len(v4.Key{})
	copy(ret[:l], e[0:KeySize])

	return ret
}

func (e Value) Timestamp() uint64 {
	return binary.LittleEndian.Uint64(e[KeySize : KeySize+8])
}

func (e Value) RevTimestamp() uint64 {
	return binary.LittleEndian.Uint64(e[KeySize+8:])
}

func NewValue(key []byte, ts, rev_ts uint64) Value {
	v := Value{}
	v.SetKey(key)
	v.SetTS(ts)
	v.SetRevTS(rev_ts)
	return v
}

type ValueInterface interface {
	AsBytes() []byte
	OtherNATKey() v4.KeyInterface
	Timestamp() uint64
	RevTimestamp() uint64
}

type MapMem map[v4.Key]Value

// LoadMapMem loads ConntrackMap into memory
func LoadMapMem(m maps.Map) (MapMem, error) {
	ret := make(MapMem)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		ks := len(v4.Key{})
		vs := len(Value{})

		var key v4.Key
		copy(key[:ks], k[:ks])

		var val Value
		copy(val[:vs], v[:vs])

		ret[key] = val
		return maps.IterNone
	})

	return ret, err
}
