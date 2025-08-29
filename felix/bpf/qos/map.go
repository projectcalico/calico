// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package qos

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

func init() {
	SetMapSize(MapParams.MaxEntries)
}

func SetMapSize(size int) {
	maps.SetSize(MapParams.VersionedName(), size)
}

const (
	KeySize    = 4 + 4
	ValueSize  = 4 + 2 + 2 + 2 + 3*2 + 8
	MaxEntries = 2 * ifstate.MaxEntries
)

var MapParams = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_qos",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      1,
	UpdatedByBPF: true,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParams)
}

type Key [8]byte

func NewKey(ifIndex uint32, ingress uint32) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:4], ifIndex)
	binary.LittleEndian.PutUint32(k[4:], ingress)

	return k
}

func (k Key) AsBytes() []byte {
	return k[:]
}

func (k Key) IfIndex() uint32 {
	return binary.LittleEndian.Uint32(k[:4])
}

func (k Key) Ingress() uint32 {
	return binary.LittleEndian.Uint32(k[4:])
}

func (k Key) String() string {
	return fmt.Sprintf("{ifIndex: %d, ingress: %d}", k.IfIndex(), k.Ingress())
}

func KeyFromBytes(b []byte) Key {
	var k Key
	copy(k[:], b)
	return k
}

type Value [ValueSize]byte

func NewValue(
	packetRate,
	packetBurst,
	packetRateTokens int16,
	packetRateLastUpdate uint64,
) Value {
	var v Value

	// skip lock (v[0:4])
	binary.LittleEndian.PutUint16(v[4:6], uint16(packetRate))
	binary.LittleEndian.PutUint16(v[6:8], uint16(packetBurst))
	binary.LittleEndian.PutUint16(v[8:10], uint16(packetRateTokens))
	// skip padding (v[10:16])
	binary.LittleEndian.PutUint64(v[16:16+8], uint64(packetRateLastUpdate))

	return v
}

func (v Value) AsBytes() []byte {
	return v[:]
}

func (v Value) PacketRate() int16 {
	return int16(binary.LittleEndian.Uint16(v[4:6]))
}

func (v Value) PacketBurst() int16 {
	return int16(binary.LittleEndian.Uint16(v[6:8]))
}

func (v Value) PacketRateTokens() int16 {
	return int16(binary.LittleEndian.Uint16(v[8:10]))
}

func (v Value) PacketRateLastUpdate() uint64 {
	return binary.LittleEndian.Uint64(v[16 : 16+8])
}

func (v Value) String() string {
	return fmt.Sprintf(
		"{PacketRate: %d, PacketBurst: %d, PacketRateTokens: %d, PacketRateLastUpdate: %d}",
		v.PacketRate(), v.PacketBurst(), v.PacketRateTokens(), v.PacketRateLastUpdate())
}

func ValueFromBytes(b []byte) Value {
	var v Value
	copy(v[:], b)
	return v
}

type MapMem map[Key]Value

func MapMemIter(m MapMem) func(k, v []byte) {
	ks := len(Key{})
	vs := len(Value{})

	return func(k, v []byte) {
		var key Key
		copy(key[:ks], k[:ks])

		var val Value
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
