// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package arp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

var MapV6Params = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    KeyV6Size,
	ValueSize:  ValueV6Size,
	MaxEntries: 10000, // max number of nodes that can forward nodeports to a single node
	Name:       "cali_v6_arp",
	Version:    2,
}

func MapV6() maps.Map {
	return maps.NewPinnedMap(MapV6Params)
}

const KeyV6Size = 20

type KeyV6 [KeyV6Size]byte

func NewKeyV6(ip net.IP, ifIndex uint32) KeyV6 {
	var k KeyV6

	ip = ip.To16()

	copy(k[:16], ip)
	binary.LittleEndian.PutUint32(k[16:20], ifIndex)

	return k
}

func (k KeyV6) IP() net.IP {
	return net.IP(k[:16])
}

func (k KeyV6) IfIndex() uint32 {
	return binary.LittleEndian.Uint32(k[16:20])
}

func (k KeyV6) String() string {
	return fmt.Sprintf("ip %s ifindex %d", k.IP(), k.IfIndex())
}

func (k KeyV6) AsBytes() []byte {
	return k[:]
}

const ValueV6Size = ValueSize

type ValueV6 = Value

type MapMemV6 map[KeyV6]ValueV6

// LoadMapMem loads ConntrackMap into memory
func LoadMapMemV6(m maps.Map) (MapMemV6, error) {
	ret := make(MapMemV6)

	ks := len(KeyV6{})
	vs := len(ValueV6{})

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		var key KeyV6
		copy(key[:ks], k[:ks])

		var val ValueV6
		copy(val[:vs], v[:vs])

		ret[key] = val
		return maps.IterNone
	})

	return ret, err
}

// MapMemIterV6 returns maps.MapIter that loads the provided MapMem
func MapMemIterV6(m MapMemV6) maps.IterCallback {
	ks := len(KeyV6{})
	vs := len(ValueV6{})

	return func(k, v []byte) maps.IteratorAction {
		var key KeyV6
		copy(key[:ks], k[:ks])

		var val ValueV6
		copy(val[:vs], v[:vs])

		m[key] = val
		return maps.IterNone
	}
}
