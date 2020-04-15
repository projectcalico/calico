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

package conntrack

import (
	"encoding/binary"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
)

// struct calico_ct_key {
//   uint32_t protocol;
//   __be32 addr_a, addr_b; // NBO
//   uint16_t port_a, port_b; // HBO
// };
const conntrackKeySize = 16
const conntrackValueSize = 64

type Key [conntrackKeySize]byte

func (k Key) AsBytes() []byte {
	return k[:]
}

func (k Key) Proto() uint8 {
	return uint8(binary.LittleEndian.Uint32(k[:4]))
}

func (k Key) AddrA() net.IP {
	return k[4:8]
}

func (k Key) PortA() uint16 {
	return binary.LittleEndian.Uint16(k[12:14])
}

func (k Key) AddrB() net.IP {
	return k[8:12]
}

func (k Key) PortB() uint16 {
	return binary.LittleEndian.Uint16(k[14:16])
}

func (k Key) String() string {
	return fmt.Sprintf("ConntrackKey{proto=%v %v:%v <-> %v:%v}",
		k.Proto(), k.AddrA(), k.PortA(), k.AddrB(), k.PortB())
}

func NewKey(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) Key {
	var k Key
	binary.LittleEndian.PutUint32(k[:4], uint32(proto))
	copy(k[4:8], ipA)
	copy(k[8:12], ipB)
	binary.LittleEndian.PutUint16(k[12:14], portA)
	binary.LittleEndian.PutUint16(k[14:16], portB)
	return k
}

// struct calico_ct_value {
//  __u64 created;
//  __u64 last_seen; // 8
//  __u8 type;     // 16
//  __u8 flags;     // 17
//
//  // Important to use explicit padding, otherwise the compiler can decide
//  // not to zero the padding bytes, which upsets the verifier.  Worse than
//  // that, debug logging often prevents such optimisation resulting in
//  // failures when debug logging is compiled out only :-).
//  __u8 pad0[6];
//  union {
//    // CALI_CT_TYPE_NORMAL and CALI_CT_TYPE_NAT_REV.
//    struct {
//      struct calico_ct_leg a_to_b; // 24
//      struct calico_ct_leg b_to_a; // 36
//
//      // CALI_CT_TYPE_NAT_REV only.
//      __u32 orig_dst;                    // 44
//      __u16 orig_port;                   // 48
//      __u8 pad1[2];                      // 50
//      __u32 tun_ip;                      // 52
//      __u32 pad3;                        // 56
//    };
//
//    // CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
//    struct {
//      struct calico_ct_key nat_rev_key;  // 24
//      __u8 pad2[8];
//    };
//  };
// };
type Value [conntrackValueSize]byte

func (e Value) Created() int64 {
	return int64(binary.LittleEndian.Uint64(e[:8]))
}

func (e Value) LastSeen() int64 {
	return int64(binary.LittleEndian.Uint64(e[8:16]))
}

func (e Value) Type() uint8 {
	return e[16]
}

func (e Value) Flags() uint8 {
	return e[17]
}

const (
	TypeNormal uint8 = iota
	TypeNATForward
	TypeNATReverse

	FlagNATOut    uint8 = 0x01
	FlagNATRwdDsr uint8 = 0x02
)

func (e Value) ReverseNATKey() Key {
	var ret Key

	l := len(Key{})
	copy(ret[:l], e[24:24+l])

	return ret
}

type Leg struct {
	Seqno       uint32
	SynSeen     bool
	AckSeen     bool
	FinSeen     bool
	RstSeen     bool
	Whitelisted bool
	Opener      bool
	Ifindex     uint32
}

func (leg Leg) Flags() uint32 {
	var flags uint32
	if leg.SynSeen {
		flags |= 1
	}
	if leg.AckSeen {
		flags |= 1 << 1
	}
	if leg.FinSeen {
		flags |= 1 << 2
	}
	if leg.RstSeen {
		flags |= 1 << 3
	}
	if leg.Whitelisted {
		flags |= 1 << 4
	}
	if leg.Opener {
		flags |= 1 << 5
	}
	return flags
}

func bitSet(bits uint32, bit uint8) bool {
	return (bits & (1 << bit)) != 0
}

func readConntrackLeg(b []byte) Leg {
	bits := binary.LittleEndian.Uint32(b[4:8])
	return Leg{
		Seqno:       binary.BigEndian.Uint32(b[0:4]),
		SynSeen:     bitSet(bits, 0),
		AckSeen:     bitSet(bits, 1),
		FinSeen:     bitSet(bits, 2),
		RstSeen:     bitSet(bits, 3),
		Whitelisted: bitSet(bits, 4),
		Opener:      bitSet(bits, 5),
		Ifindex:     binary.LittleEndian.Uint32(b[8:12]),
	}
}

type EntryData struct {
	A2B      Leg
	B2A      Leg
	OrigDst  net.IP
	OrigPort uint16
	TunIP    net.IP
}

func (data EntryData) Established() bool {
	return data.A2B.SynSeen && data.A2B.AckSeen && data.B2A.SynSeen && data.B2A.AckSeen
}

func (data EntryData) RSTSeen() bool {
	return data.A2B.RstSeen || data.B2A.RstSeen
}

func (data EntryData) FINsSeen() bool {
	return data.A2B.FinSeen && data.B2A.FinSeen
}

func (data EntryData) FINsSeenDSR() bool {
	return data.A2B.FinSeen || data.B2A.FinSeen
}

func (e Value) Data() EntryData {
	ip := e[40:44]
	tip := e[48:52]
	return EntryData{
		A2B:      readConntrackLeg(e[24:32]),
		B2A:      readConntrackLeg(e[32:40]),
		OrigDst:  net.IPv4(ip[0], ip[1], ip[2], ip[3]),
		OrigPort: binary.LittleEndian.Uint16(e[44:46]),
		TunIP:    net.IPv4(tip[0], tip[1], tip[2], tip[3]),
	}
}

func (e Value) String() string {
	flagsStr := ""
	flags := e.Flags()

	if flags == 0 {
		flagsStr = " <none>"
	} else {
		if flags&FlagNATOut != 0 {
			flagsStr += " nat-out"
		}

		if flags&FlagNATRwdDsr != 0 {
			flagsStr += " fwd-dsr"
		}
	}

	ret := fmt.Sprintf("Entry{Type:%d, Created:%d, LastSeen:%d, Flags:%s ",
		e.Type(), e.Created(), e.LastSeen(), flagsStr)

	switch e.Type() {
	case TypeNATForward:
		ret += fmt.Sprintf("REVKey : %s", e.ReverseNATKey().String())
	case TypeNormal, TypeNATReverse:
		ret += fmt.Sprintf("Data: %+v", e.Data())
	default:
		ret += "TYPE INVALID"
	}

	return ret + "}"
}

func (e Value) IsForwardDSR() bool {
	return e.Flags()&FlagNATRwdDsr != 0
}

var MapParams = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_ct",
	Type:       "hash",
	KeySize:    conntrackKeySize,
	ValueSize:  conntrackValueSize,
	MaxEntries: 512000,
	Name:       "cali_v4_ct",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParams)
}

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

func keyFromBytes(k []byte) Key {
	var ctKey Key
	if len(k) != len(ctKey) {
		log.Panic("Key has unexpected length")
	}
	copy(ctKey[:], k[:])
	return ctKey
}

func entryFromBytes(v []byte) Value {
	var ctVal Value
	if len(v) != len(ctVal) {
		log.Panic("Value has unexpected length")
	}
	copy(ctVal[:], v[:])
	return ctVal
}

type MapMem map[Key]Value

// LoadMapMem loads ConntrackMap into memory
func LoadMapMem(m bpf.Map) (MapMem, error) {
	ret := make(MapMem)

	err := m.Iter(func(k, v []byte) {
		ks := len(Key{})
		vs := len(Value{})

		var key Key
		copy(key[:ks], k[:ks])

		var val Value
		copy(val[:vs], v[:vs])

		ret[key] = val
	})

	return ret, err
}
