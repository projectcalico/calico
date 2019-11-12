// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package maps

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
const natKeySize = 8

// struct calico_nat_v4_value {
//    uint32_t id;
//    uint32_t count;
// };
const natValueSize = 8

// struct calico_nat_secondary_v4_key {
//   uint32_t id;
//   uint32_t ordinal;
// };
const natBackendKeySize = 8

// struct calico_nat_dest {
//    uint32_t addr;
//    uint16_t port;
//    uint8_t pad[2];
// };
const natBackendValueSize = 8

type NATKey [natKeySize]byte

func NewNATKey(addr net.IP, port uint16, protocol uint8) NATKey {
	var k NATKey
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	k[6] = protocol
	return k
}

func (k NATKey) Proto() uint8 {
	return k[6]
}

func (k NATKey) Addr() net.IP {
	return k[:4]
}

func (k NATKey) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k NATKey) String() string {
	return fmt.Sprintf("NATKey{Proto:%v Addr:%v Port:%v}", k.Proto(), k.Addr(), k.Port())
}

type NATValue [natValueSize]byte

func NewNATValue(id, count uint32) NATValue {
	var v NATValue
	binary.LittleEndian.PutUint32(v[:4], id)
	binary.LittleEndian.PutUint32(v[4:8], count)
	return v
}

func (v NATValue) ID() uint32 {
	return binary.LittleEndian.Uint32(v[:4])
}

func (v NATValue) Count() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v NATValue) String() string {
	return fmt.Sprintf("NATValue{ID:%d,Count:%d}", v.ID(), v.Count())
}

type NATBackendKey [natBackendKeySize]byte

func NewNATBackendKey(id, ordinal uint32) NATBackendKey {
	var v NATBackendKey
	binary.LittleEndian.PutUint32(v[:4], id)
	binary.LittleEndian.PutUint32(v[4:8], ordinal)
	return v
}

func (v NATBackendKey) ID() uint32 {
	return binary.LittleEndian.Uint32(v[:4])
}

func (v NATBackendKey) Count() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v NATBackendKey) String() string {
	return fmt.Sprintf("NATBackendKey{ID:%d,Ordinal:%d}", v.ID(), v.Count())
}

type NATBackendValue [natBackendValueSize]byte

func NewNATBackendValue(addr net.IP, port uint16) NATBackendValue {
	var k NATBackendValue
	addr = addr.To4()
	if len(addr) != 4 {
		log.WithField("ip", addr).Panic("Bad IP")
	}
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	return k
}

func (k NATBackendValue) Addr() net.IP {
	return k[:4]
}

func (k NATBackendValue) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k NATBackendValue) String() string {
	return fmt.Sprintf("NATBackendValue{Addr:%v Port:%v}", k.Addr(), k.Port())
}

func NATMap() bpf.Map {
	return bpf.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_nat_v4",
		Type:       "hash",
		KeySize:    natKeySize,
		ValueSize:  natValueSize,
		MaxEntries: 511000,
		Name:       "cali_nat_v4",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
}

func BackendMap() bpf.Map {
	return bpf.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_natbe_v4",
		Type:       "hash",
		KeySize:    natBackendKeySize,
		ValueSize:  natBackendValueSize,
		MaxEntries: 510000,
		Name:       "cali_natbe_v4",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
}

// NATMapMem represents NATMap loaded into memory
type NATMapMem map[NATKey]NATValue

// Equal compares keys and values of the NATMapMem
func (m NATMapMem) Equal(cmp NATMapMem) bool {
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

// LoadNATMap loads the NAT map into a go map or returns an error
func LoadNATMap(m bpf.Map) (NATMapMem, error) {
	ret := make(NATMapMem)

	err := m.Iter(NATMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// NATMapMemIter returns bpf.MapIter that loads the provided NATMapMem
func NATMapMemIter(m NATMapMem) bpf.MapIter {
	ks := len(NATKey{})
	vs := len(NATValue{})

	return func(k, v []byte) {
		var key NATKey
		copy(key[:ks], k[:ks])

		var val NATValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}

// NATBackendMapMem represents a NATBackend loaded into memory
type NATBackendMapMem map[NATBackendKey]NATBackendValue

// Equal compares keys and values of the NATBackendMapMem
func (m NATBackendMapMem) Equal(cmp NATBackendMapMem) bool {
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

// LoadNATBackendMap loads the NATBackend map into a go map or returns an error
func LoadNATBackendMap(m bpf.Map) (NATBackendMapMem, error) {
	ret := make(NATBackendMapMem)

	err := m.Iter(NATBackendMapMemIter(ret))
	if err != nil {
		ret = nil
	}

	return ret, err
}

// NATBackendMapMemIter returns bpf.MapIter that loads the provided NATBackendMapMem
func NATBackendMapMemIter(m NATBackendMapMem) bpf.MapIter {
	ks := len(NATBackendKey{})
	vs := len(NATBackendValue{})

	return func(k, v []byte) {
		var key NATBackendKey
		copy(key[:ks], k[:ks])

		var val NATBackendValue
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
