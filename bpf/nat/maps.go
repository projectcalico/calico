// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package nat

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

// struct calico_nat_v4_key {
//    uint32_t addr; // NBO
//    uint16_t port; // HBO
//    uint8_t protocol;
//    uint8_t pad;
// };
const frontendKeySize = 8

// struct calico_nat_v4_value {
//    uint32_t id;
//    uint32_t count;
//    uint32_t local;
//    uint32_t padding;
// };
const frontendValueSize = 16

// struct calico_nat_secondary_v4_key {
//   uint32_t id;
//   uint32_t ordinal;
// };
const backendKeySize = 8

// struct calico_nat_dest {
//    uint32_t addr;
//    uint16_t port;
//    uint8_t pad[2];
// };
const backendValueSize = 8

type FrontendKey [frontendKeySize]byte

func NewNATKey(addr net.IP, port uint16, protocol uint8) FrontendKey {
	var k FrontendKey
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	k[6] = protocol
	return k
}

func (k FrontendKey) Proto() uint8 {
	return k[6]
}

func (k FrontendKey) Addr() net.IP {
	return k[:4]
}

func (k FrontendKey) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k FrontendKey) AsBytes() []byte {
	return k[:]
}

func (k FrontendKey) String() string {
	return fmt.Sprintf("NATKey{Proto:%v Addr:%v Port:%v}", k.Proto(), k.Addr(), k.Port())
}

type FrontendValue [frontendValueSize]byte

func NewNATValue(id uint32, count, local uint32) FrontendValue {
	var v FrontendValue
	binary.LittleEndian.PutUint32(v[:4], id)
	binary.LittleEndian.PutUint32(v[4:8], count)
	binary.LittleEndian.PutUint32(v[8:12], local)
	return v
}

func (v FrontendValue) ID() uint32 {
	return binary.LittleEndian.Uint32(v[:4])
}

func (v FrontendValue) Count() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v FrontendValue) LocalCount() uint32 {
	return binary.LittleEndian.Uint32(v[8:12])
}

func (v FrontendValue) String() string {
	return fmt.Sprintf("NATValue{ID:%d,Count:%d,LocalCount:%d}", v.ID(), v.Count(), v.LocalCount())
}

func (v FrontendValue) AsBytes() []byte {
	return v[:]
}

type BackendKey [backendKeySize]byte

func NewNATBackendKey(id, ordinal uint32) BackendKey {
	var v BackendKey
	binary.LittleEndian.PutUint32(v[:4], id)
	binary.LittleEndian.PutUint32(v[4:8], ordinal)
	return v
}

func (v BackendKey) ID() uint32 {
	return binary.LittleEndian.Uint32(v[:4])
}

func (v BackendKey) Count() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v BackendKey) String() string {
	return fmt.Sprintf("NATBackendKey{ID:%d,Ordinal:%d}", v.ID(), v.Count())
}

func (k BackendKey) AsBytes() []byte {
	return k[:]
}

type BackendValue [backendValueSize]byte

func NewNATBackendValue(addr net.IP, port uint16) BackendValue {
	var k BackendValue
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	return k
}

func (k BackendValue) Addr() net.IP {
	return k[:4]
}

func (k BackendValue) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k BackendValue) String() string {
	return fmt.Sprintf("NATBackendValue{Addr:%v Port:%v}", k.Addr(), k.Port())
}

func (k BackendValue) AsBytes() []byte {
	return k[:]
}

var FrontendMapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_nat_fe",
	Type:       "hash",
	KeySize:    frontendKeySize,
	ValueSize:  frontendValueSize,
	MaxEntries: 511000,
	Name:       "cali_v4_nat_fe",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func FrontendMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(FrontendMapParameters)
}

var BackendMapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_nat_be",
	Type:       "hash",
	KeySize:    backendKeySize,
	ValueSize:  backendValueSize,
	MaxEntries: 510000,
	Name:       "cali_v4_nat_be",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func BackendMap(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(BackendMapParameters)
}

// NATMapMem represents FrontendMap loaded into memory
type MapMem map[FrontendKey]FrontendValue

// Equal compares keys and values of the NATMapMem
func (m MapMem) Equal(cmp MapMem) bool {
	if len(m) != len(cmp) {
		return false
	}

	for k, v := range m {
		v2, ok := cmp[k]
		if !ok || v != v2 {
			return false
		}
	}

	return true
}

// LoadFrontendMap loads the NAT map into a go map or returns an error
func LoadFrontendMap(m bpf.Map) (MapMem, error) {
	ret := make(MapMem)

	err := m.Iter(MapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// MapMemIter returns bpf.MapIter that loads the provided NATMapMem
func MapMemIter(m MapMem) bpf.MapIter {
	ks := len(FrontendKey{})
	vs := len(FrontendValue{})

	return func(k, v []byte) {
		var key FrontendKey
		copy(key[:ks], k[:ks])

		var val FrontendValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// NATBackendMapMem represents a NATBackend loaded into memory
type BackendMapMem map[BackendKey]BackendValue

// Equal compares keys and values of the NATBackendMapMem
func (m BackendMapMem) Equal(cmp BackendMapMem) bool {
	if len(m) != len(cmp) {
		return false
	}

	for k, v := range m {
		v2, ok := cmp[k]
		if !ok || v != v2 {
			return false
		}
	}

	return true
}

// LoadBackendMap loads the NATBackend map into a go map or returns an error
func LoadBackendMap(m bpf.Map) (BackendMapMem, error) {
	ret := make(BackendMapMem)

	err := m.Iter(BackendMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// BackendMapMemIter returns bpf.MapIter that loads the provided NATBackendMapMem
func BackendMapMemIter(m BackendMapMem) bpf.MapIter {
	ks := len(BackendKey{})
	vs := len(BackendValue{})

	return func(k, v []byte) {
		var key BackendKey
		copy(key[:ks], k[:ks])

		var val BackendValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
