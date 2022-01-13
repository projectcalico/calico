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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
)

var MapParams = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_arp",
	Type:       "lru_hash",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 10000, // max number of nodes that can forward nodeports to a single node
	Name:       "cali_v4_arp",
	Version:    2,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParams)
}

const KeySize = 8

type Key [KeySize]byte

func NewKey(ip net.IP, ifIndex uint32) Key {
	var k Key

	ip = ip.To4()
	if len(ip) != 4 {
		log.WithField("ip", ip).Panic("Bad IP")
	}

	copy(k[:4], ip)
	binary.LittleEndian.PutUint32(k[4:8], ifIndex)

	return k
}

func (k Key) IP() net.IP {
	return net.IP(k[:4])
}

func (k Key) IfIndex() uint32 {
	return binary.LittleEndian.Uint32(k[4:8])
}

func (k Key) String() string {
	return fmt.Sprintf("ip %s ifindex %d", k.IP(), k.IfIndex())
}

func (k Key) AsBytes() []byte {
	return k[:]
}

const ValueSize = 12

type Value [ValueSize]byte

func NewValue(macSrc, macDst net.HardwareAddr) Value {
	var v Value

	copy(v[0:6], macSrc)
	copy(v[6:12], macDst)

	return v
}

func (v Value) SrcMAC() net.HardwareAddr {
	return net.HardwareAddr(v[0:6])
}

func (v Value) DstMAC() net.HardwareAddr {
	return net.HardwareAddr(v[6:12])
}

func (v Value) String() string {
	return fmt.Sprintf("src: %s dst %s", v.SrcMAC(), v.DstMAC())
}

func (v Value) AsBytes() []byte {
	return v[:]
}

type MapMem map[Key]Value

// LoadMapMem loads ConntrackMap into memory
func LoadMapMem(m bpf.Map) (MapMem, error) {
	ret := make(MapMem)

	err := m.Iter(func(k, v []byte) bpf.IteratorAction {
		ks := len(Key{})
		vs := len(Value{})

		var key Key
		copy(key[:ks], k[:ks])

		var val Value
		copy(val[:vs], v[:vs])

		ret[key] = val
		return bpf.IterNone
	})

	return ret, err
}

// MapMemIter returns bpf.MapIter that loads the provided MapMem
func MapMemIter(m MapMem) bpf.IterCallback {
	ks := len(Key{})
	vs := len(Value{})

	return func(k, v []byte) bpf.IteratorAction {
		var key Key
		copy(key[:ks], k[:ks])

		var val Value
		copy(val[:vs], v[:vs])

		m[key] = val
		return bpf.IterNone
	}
}
