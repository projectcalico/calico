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

type conntrackManager struct {
	ctMap bpf.Map
}

// struct calico_ct_key {
//   uint32_t protocol;
//   __be32 addr_a, addr_b; // NBO
//   uint16_t port_a, port_b; // HBO
// };
const conntrackKeySize = 16
const conntrackValueSize = 48

type ConntrackKey [conntrackKeySize]byte

func (k ConntrackKey) Proto() uint8 {
	return uint8(binary.LittleEndian.Uint32(k[:4]))
}

func (k ConntrackKey) AddrA() net.IP {
	return k[4:8]
}

func (k ConntrackKey) PortA() uint16 {
	return binary.LittleEndian.Uint16(k[12:14])
}

func (k ConntrackKey) AddrB() net.IP {
	return k[8:12]
}

func (k ConntrackKey) PortB() uint16 {
	return binary.LittleEndian.Uint16(k[14:16])
}

func (k ConntrackKey) String() string {
	return fmt.Sprintf("ConntrackKey{proto=%v %v:%v <-> %v:%v}",
		k.Proto(), k.AddrA(), k.PortA(), k.AddrB(), k.PortB())
}

type ConntrackEntry [conntrackValueSize]byte

func (e ConntrackEntry) Type() uint8 {
	return uint8(e[16])
}

const (
	ConntrackTypeNormal uint8 = iota
	ConntrackTypeNatFwd
	ConntrackTypeNatRev
)

func (e ConntrackEntry) FwdKey() ConntrackKey {
	var ret ConntrackKey

	l := len(ConntrackKey{})
	copy(ret[:l], e[24:24+l])

	return ret
}

type ConntrackLeg struct {
	Seqno      uint32
	SynSeen    bool
	AckSeen    bool
	FinSeen    bool
	RstSeen    bool
	Whitlisted bool
	Opener     bool
}

func bitSet(bits uint32, bit uint8) bool {
	return (bits & (1 << bit)) != 0
}

func readConntrackLeg(b []byte) ConntrackLeg {
	bits := binary.LittleEndian.Uint32(b[4:8])
	return ConntrackLeg{
		Seqno:      binary.BigEndian.Uint32(b[0:4]),
		SynSeen:    bitSet(bits, 0),
		AckSeen:    bitSet(bits, 1),
		FinSeen:    bitSet(bits, 2),
		RstSeen:    bitSet(bits, 3),
		Whitlisted: bitSet(bits, 4),
		Opener:     bitSet(bits, 5),
	}
}

type ConntrackEntryData struct {
	A2B      ConntrackLeg
	B2A      ConntrackLeg
	OrigDst  net.IP
	OrigPort uint16
}

func (e ConntrackEntry) Data() ConntrackEntryData {
	ip := e[40:44]
	return ConntrackEntryData{
		A2B:      readConntrackLeg(e[24:32]),
		B2A:      readConntrackLeg(e[32:40]),
		OrigDst:  net.IPv4(ip[0], ip[1], ip[2], ip[3]),
		OrigPort: binary.LittleEndian.Uint16(e[44:46]),
	}
}

func (e ConntrackEntry) String() string {
	ret := fmt.Sprintf("ConntrackEntry{Type :%d, ", e.Type())

	switch e.Type() {
	case ConntrackTypeNatFwd:
		ret += fmt.Sprintf("REVKey : %s", e.FwdKey().String())
	case ConntrackTypeNormal, ConntrackTypeNatRev:
		ret += fmt.Sprintf("Data: %+v", e.Data())
	default:
		ret += "TYPE INVALID"
	}

	return ret + "}"
}

func newBPFConntrackManager() *conntrackManager {
	return &conntrackManager{
		ctMap: ConntrackMap(),
	}
}

func ConntrackMap() bpf.Map {
	return bpf.NewPinnedMap(
		"calico_ct_map_v4",
		"/sys/fs/bpf/tc/globals/calico_ct_map_v4",
		"hash",
		conntrackKeySize,
		conntrackValueSize,
		512000,
		unix.BPF_F_NO_PREALLOC)
}

func (m *conntrackManager) OnUpdate(msg interface{}) {
}

func (m *conntrackManager) CompleteDeferredWork() error {
	err := m.ctMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create Conntrack map")
	}
	return nil
}
