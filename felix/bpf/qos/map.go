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

// Packet-rate (cali_qos) and connection-limit (cali_qos_conn) live in two
// separate BPF maps sharing the same key shape. They were split because the
// userspace ConnLimitScanner has to write current_count back to the map,
// and a shared value forced a read-modify-write that would clobber the
// BPF dataplane's running token-bucket state (BPF_F_LOCK only covers the
// write — locks don't span syscall boundaries). With two maps, each
// writer owns its own field group exclusively.

func init() {
	SetMapSize(MapParams.MaxEntries)
	SetConnMapSize(ConnMapParams.MaxEntries)
}

func SetMapSize(size int) {
	maps.SetSize(MapParams.VersionedName(), size)
}

func SetConnMapSize(size int) {
	maps.SetSize(ConnMapParams.VersionedName(), size)
}

const (
	KeySize = 4 + 2 + 2
	// IP family constants used in the QoS map key. Values match the IP
	// version number to keep BPF-side debug output legible.
	IPFamilyV4 uint16 = 4
	IPFamilyV6 uint16 = 6
	// ValueSize: lock(4) + packetRate(2) + packetBurst(2) +
	// packetRateTokens(2) + padding(6) + packetRateLastUpdate(8) = 24
	ValueSize = 4 + 2 + 2 + 2 + 3*2 + 8
	// ConnValueSize: lock(4) + maxConnections(4) + currentCount(4) = 12
	ConnValueSize = 4 + 4 + 4
	// 4 entries per interface: 2 directions × 2 IP families.
	MaxEntries = 4 * ifstate.MaxEntries
)

var MapParams = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_qos",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      2,
	UpdatedByBPF: true,
}

var ConnMapParams = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ConnValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_qos_conn",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      1,
	UpdatedByBPF: true,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParams)
}

func ConnMap() maps.Map {
	return maps.NewPinnedMap(ConnMapParams)
}

type Key [KeySize]byte

func NewKey(ifIndex uint32, ingress, family uint16) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:4], ifIndex)
	binary.LittleEndian.PutUint16(k[4:6], ingress)
	binary.LittleEndian.PutUint16(k[6:8], family)

	return k
}

func (k Key) AsBytes() []byte {
	return k[:]
}

func (k Key) IfIndex() uint32 {
	return binary.LittleEndian.Uint32(k[:4])
}

func (k Key) Ingress() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k Key) Family() uint16 {
	return binary.LittleEndian.Uint16(k[6:8])
}

func (k Key) String() string {
	return fmt.Sprintf("{ifIndex: %d, ingress: %d, family: %d}", k.IfIndex(), k.Ingress(), k.Family())
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
	binary.LittleEndian.PutUint64(v[16:24], uint64(packetRateLastUpdate))

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
	return binary.LittleEndian.Uint64(v[16:24])
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

type ConnValue [ConnValueSize]byte

func NewConnValue(maxConnections, currentCount uint32) ConnValue {
	var v ConnValue

	// skip lock (v[0:4])
	binary.LittleEndian.PutUint32(v[4:8], maxConnections)
	binary.LittleEndian.PutUint32(v[8:12], currentCount)

	return v
}

func (v ConnValue) AsBytes() []byte {
	return v[:]
}

func (v ConnValue) MaxConnections() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v ConnValue) CurrentCount() uint32 {
	return binary.LittleEndian.Uint32(v[8:12])
}

func (v ConnValue) String() string {
	return fmt.Sprintf("{MaxConnections: %d, CurrentCount: %d}", v.MaxConnections(), v.CurrentCount())
}

func ConnValueFromBytes(b []byte) ConnValue {
	var v ConnValue
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

type ConnMapMem map[Key]ConnValue

func ConnMapMemIter(m ConnMapMem) func(k, v []byte) {
	ks := len(Key{})
	vs := len(ConnValue{})

	return func(k, v []byte) {
		var key Key
		copy(key[:ks], k[:ks])

		var val ConnValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
