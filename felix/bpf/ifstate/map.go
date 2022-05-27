// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package ifstate

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
)

const (
	KeySize    = 4
	ValueSize  = 4
	MaxEntries = 1000
)

const (
	FlgWEP   = uint32(0x1)
	FlgReady = uint32(0x2)
)

var MapParams = bpf.MapParameters{
	Filename:     "/sys/fs/bpf/tc/globals/cali_iface",
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_iface",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      2,
	UpdatedByBPF: false,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParams)
}

type Key [4]byte

func NewKey(ifIndex uint32) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:], ifIndex)

	return k
}

func (k Key) AsBytes() []byte {
	return k[:]
}

func (k Key) IfIndex() uint32 {
	return binary.LittleEndian.Uint32(k[:])
}

type Value [4]byte

func NewValue(flags uint32) Value {
	var v Value

	binary.LittleEndian.PutUint32(v[:], flags)

	return v
}

func (v Value) AsBytes() []byte {
	return v[:]
}

func (v Value) Flags() uint32 {
	return binary.LittleEndian.Uint32(v[:])
}
