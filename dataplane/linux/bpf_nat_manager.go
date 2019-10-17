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

package intdataplane

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

type bpfNATManager struct {
	natMap     bpf.Map
	backendMap bpf.Map
}

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

func NewNatKey(addr net.IP, port uint16, protocol uint8) NATKey {
	var k NATKey
	copy(k[:4], addr)
	binary.LittleEndian.PutUint16(k[4:6], port)
	k[7] = protocol
	return k
}

func (k NATKey) Proto() uint8 {
	return k[7]
}

func (k NATKey) Addr() net.IP {
	return k[:4]
}

func (k NATKey) Port() uint16 {
	return binary.LittleEndian.Uint16(k[4:6])
}

func (k NATKey) String() string {
	return fmt.Sprintf("proto=%v %v:%v", k.Proto(), k.Addr(), k.Port())
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
	return fmt.Sprintf("%v:%v", k.Addr(), k.Port())
}

func newBPFNATManager() *bpfNATManager {
	return &bpfNATManager{
		natMap:     NATMap(),
		backendMap: BackendMap(),
	}
}

func NATMap() bpf.Map {
	return bpf.NewPinnedMap(
		"calico_nat_map_v4",
		"/sys/fs/bpf/tc/globals/calico_nat_map_v4",
		"hash",
		natKeySize,
		natValueSize,
		511000,
		unix.BPF_F_NO_PREALLOC)
}

func BackendMap() bpf.Map {
	return bpf.NewPinnedMap(
		"calico_nat_secondary_map_v4",
		"/sys/fs/bpf/tc/globals/calico_nat_secondary_map_v4",
		"hash",
		natKeySize,
		natValueSize,
		510000,
		unix.BPF_F_NO_PREALLOC)
}

func (m *bpfNATManager) OnUpdate(msg interface{}) {
}

func (m *bpfNATManager) CompleteDeferredWork() error {
	err := m.natMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create NAT map")
	}
	err = m.backendMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create NAT map")
	}
	return nil
}
