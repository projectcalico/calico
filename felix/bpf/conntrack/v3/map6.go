// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package v3

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

//	struct calico_ct_key {
//	  uint32_t protocol;
//	  __be32 addr_a, addr_b; // NBO
//	  uint16_t port_a, port_b; // HBO
//	};
const KeyV6Size = 40
const ValueV6Size = 128

type KeyV6 [KeyV6Size]byte

func (k KeyV6) AsBytes() []byte {
	return k[:]
}

func (k KeyV6) Proto() uint8 {
	return uint8(binary.LittleEndian.Uint32(k[:4]))
}

func (k KeyV6) AddrA() net.IP {
	return k[4:20]
}

func (k KeyV6) PortA() uint16 {
	return binary.LittleEndian.Uint16(k[36:38])
}

func (k KeyV6) AddrB() net.IP {
	return k[20:36]
}

func (k KeyV6) PortB() uint16 {
	return binary.LittleEndian.Uint16(k[38:40])
}

func (k KeyV6) String() string {
	return fmt.Sprintf("ConntrackKey{proto=%v %v:%v <-> %v:%v}",
		k.Proto(), k.AddrA(), k.PortA(), k.AddrB(), k.PortB())
}

func (k KeyV6) Upgrade() maps.Upgradable {
	panic("conntrack map key already at its latest version")
}

func NewKeyV6(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) KeyV6 {
	var k KeyV6
	binary.LittleEndian.PutUint32(k[:4], uint32(proto))
	copy(k[4:20], ipA.To16())
	copy(k[20:36], ipB.To16())
	binary.LittleEndian.PutUint16(k[36:38], portA)
	binary.LittleEndian.PutUint16(k[38:40], portB)
	return k
}

// struct calico_ct_value {
//  __u64 rst_seen;
//  __u64 last_seen; // 8
//  __u8 type;     // 16
//  __u8 flags;     // 17
//
//  // Important to use explicit padding, otherwise the compiler can decide
//  // not to zero the padding bytes, which upsets the verifier.  Worse than
//  // that, debug logging often prevents such optimisation resulting in
//  // failures when debug logging is compiled out only :-).
//  __u8 pad0[5];
//  __u8 flags2;
//  union {
//    // CALI_CT_TYPE_NORMAL and CALI_CT_TYPE_NAT_REV.
//    struct {
//      struct calico_ct_leg a_to_b; // 24
//      struct calico_ct_leg b_to_a; // 36
//
//      // CALI_CT_TYPE_NAT_REV only.
//      __u32 orig_dst;                    // 48
//      __u16 orig_port;                   // 52
//      __u8 pad1[2];                      // 54
//      __u32 tun_ip;                      // 56
//      __u32 pad3;                        // 60
//    };
//
//    // CALI_CT_TYPE_NAT_FWD; key for the CALI_CT_TYPE_NAT_REV entry.
//    struct {
//      struct calico_ct_key nat_rev_key;  // 24
//      __u8 pad2[8];
//    };
//  };
// };

const (
	VoRSTSeenV6   int = 0
	VoLastSeenV6  int = 8
	VoTypeV6      int = 16
	VoFlagsV6     int = 17
	VoFlags2V6    int = 23
	VoRevKeyV6    int = 24
	VoLegABV6     int = 24
	VoLegBAV6     int = 48
	VoTunIPV6     int = 72
	VoOrigIPV6    int = VoTunIPV6 + 16
	VoOrigPortV6  int = VoOrigIPV6 + 16
	VoOrigSPortV6 int = VoOrigPortV6 + 2
	VoOrigSIPV6   int = VoOrigSPortV6 + 2
	VoNATSPortV6  int = VoRevKeyV6 + KeyV6Size
)

type ValueV6 [ValueV6Size]byte

func (e ValueV6) RSTSeen() int64 {
	return int64(binary.LittleEndian.Uint64(e[VoRSTSeenV6 : VoRSTSeenV6+8]))
}

func (e ValueV6) LastSeen() int64 {
	return int64(binary.LittleEndian.Uint64(e[VoLastSeenV6 : VoLastSeenV6+8]))
}

func (e ValueV6) Type() uint8 {
	return e[VoTypeV6]
}

func (e ValueV6) Flags() uint16 {
	return uint16(e[VoFlagsV6]) | (uint16(e[VoFlags2]) << 8)
}

// OrigIP returns the original destination IP, valid only if Type() is TypeNormal or TypeNATReverse
func (e ValueV6) OrigIP() net.IP {
	return e[VoOrigIPV6 : VoOrigIPV6+16]
}

// OrigPort returns the original destination port, valid only if Type() is TypeNormal or TypeNATReverse
func (e ValueV6) OrigPort() uint16 {
	return binary.LittleEndian.Uint16(e[VoOrigPortV6 : VoOrigPortV6+2])
}

// OrigSPort returns the original source port, valid only if Type() is
// TypeNATReverse and if the value returned is non-zero.
func (e ValueV6) OrigSPort() uint16 {
	return binary.LittleEndian.Uint16(e[VoOrigSPortV6 : VoOrigSPortV6+2])
}

// NATSPort returns the port to SNAT to, valid only if Type() is TypeNATForward.
func (e ValueV6) NATSPort() uint16 {
	return binary.LittleEndian.Uint16(e[VoNATSPortV6 : VoNATSPortV6+2])
}

// OrigSrcIP returns the original source IP.
func (e ValueV6) OrigSrcIP() net.IP {
	return e[VoOrigSIPV6 : VoOrigSIPV6+16]
}

func (e ValueV6) ReverseNATKey() KeyInterface {
	var ret KeyV6

	l := len(KeyV6{})
	copy(ret[:l], e[VoRevKeyV6:VoRevKeyV6+l])

	return ret
}

// AsBytes returns the value as slice of bytes
func (e ValueV6) AsBytes() []byte {
	return e[:]
}

func (e *ValueV6) SetLegA2B(leg Leg) {
	copy(e[VoLegABV6:VoLegABV6+legSize], leg.AsBytes())
}

func (e *ValueV6) SetLegB2A(leg Leg) {
	copy(e[VoLegBAV6:VoLegBAV6+legSize], leg.AsBytes())
}

func (e *ValueV6) SetOrigSport(sport uint16) {
	binary.LittleEndian.PutUint16(e[VoOrigSPortV6:VoOrigSPortV6+2], sport)
}

func (e *ValueV6) SetNATSport(sport uint16) {
	binary.LittleEndian.PutUint16(e[VoNATSPortV6:VoNATSPortV6+2], sport)
}

func initValueV6(v *ValueV6, lastSeen time.Duration, typ uint8, flags uint16) {
	binary.LittleEndian.PutUint64(v[VoLastSeenV6:VoLastSeenV6+8], uint64(lastSeen))
	v[VoTypeV6] = typ
	v[VoFlagsV6] = byte(flags & 0xff)
	v[VoFlags2] = byte((flags >> 8) & 0xff)
}

// NewValueV6Normal creates a new ValueV6 of type TypeNormal based on the given parameters
func NewValueV6Normal(lastSeen time.Duration, flags uint16, legA, legB Leg) ValueV6 {
	v := ValueV6{}

	initValueV6(&v, lastSeen, TypeNormal, flags)

	v.SetLegA2B(legA)
	v.SetLegB2A(legB)

	return v
}

// NewValueV6NATForward creates a new ValueV6 of type TypeNATForward for the given
// arguments and the reverse key
func NewValueV6NATForward(lastSeen time.Duration, flags uint16, revKey KeyV6) ValueV6 {
	v := ValueV6{}

	initValueV6(&v, lastSeen, TypeNATForward, flags)

	copy(v[VoRevKeyV6:VoRevKeyV6+KeySize], revKey.AsBytes())

	return v
}

// NewValueV6NATReverse creates a new ValueV6 of type TypeNATReverse for the given
// arguments and reverse parameters
func NewValueV6NATReverse(lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP net.IP, origPort uint16) ValueV6 {
	v := ValueV6{}

	initValueV6(&v, lastSeen, TypeNATReverse, flags)

	v.SetLegA2B(legA)
	v.SetLegB2A(legB)

	copy(v[VoOrigIPV6:VoOrigIPV6+16], origIP.To4())
	binary.LittleEndian.PutUint16(v[VoOrigPortV6:VoOrigPortV6+2], origPort)

	copy(v[VoTunIPV6:VoTunIPV6+16], tunnelIP.To4())

	return v
}

// NewValueV6NATReverseSNAT in addition to NewValueV6NATReverse sets the orig source IP
func NewValueV6NATReverseSNAT(lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP, origSrcIP net.IP, origPort uint16) ValueV6 {
	v := NewValueV6NATReverse(lastSeen, flags, legA, legB, tunnelIP, origIP, origPort)
	copy(v[VoOrigSIPV6:VoOrigSIPV6+16], origIP.To4())

	return v
}

func readConntrackLegV6(b []byte) Leg {
	bits := binary.LittleEndian.Uint32(b[legExtra+4 : legExtra+8])
	return Leg{
		Bytes:    binary.LittleEndian.Uint64(b[0:8]),
		Packets:  binary.LittleEndian.Uint32(b[8:12]),
		Seqno:    binary.BigEndian.Uint32(b[legExtra+0 : legExtra+4]),
		SynSeen:  bitSet(bits, 0),
		AckSeen:  bitSet(bits, 1),
		FinSeen:  bitSet(bits, 2),
		RstSeen:  bitSet(bits, 3),
		Approved: bitSet(bits, 4),
		Opener:   bitSet(bits, 5),
		Ifindex:  binary.LittleEndian.Uint32(b[legExtra+8 : legExtra+12]),
	}
}

func (e ValueV6) Data() EntryData {
	ip := e[VoOrigIPV6 : VoOrigIPV6+16]
	tip := e[VoTunIPV6 : VoTunIPV6+16]
	sip := e[VoOrigSIPV6 : VoOrigSIPV6+16]
	return EntryData{
		A2B:       readConntrackLegV6(e[VoLegABV6 : VoLegABV6+legSize]),
		B2A:       readConntrackLegV6(e[VoLegBAV6 : VoLegBAV6+legSize]),
		OrigDst:   ip,
		OrigSrc:   sip,
		OrigPort:  binary.LittleEndian.Uint16(e[VoOrigPortV6 : VoOrigPortV6+2]),
		OrigSPort: binary.LittleEndian.Uint16(e[VoOrigPortV6+2 : VoOrigPortV6+4]),
		TunIP:     tip,
	}
}

func (e ValueV6) String() string {
	flagsStr := ""
	flags := e.Flags()

	if flags == 0 {
		flagsStr = " <none>"
	} else {
		flagsStr = fmt.Sprintf(" 0x%x", flags)
		if flags&FlagNATOut != 0 {
			flagsStr += " nat-out"
		}

		if flags&FlagNATFwdDsr != 0 {
			flagsStr += " fwd-dsr"
		}

		if flags&FlagNATNPFwd != 0 {
			flagsStr += " np-fwd"
		}

		if flags&FlagSkipFIB != 0 {
			flagsStr += " skip-fib"
		}

		if flags&FlagExtLocal != 0 {
			flagsStr += " ext-local"
		}

		if flags&FlagViaNATIf != 0 {
			flagsStr += " via-nat-iface"
		}

		if flags&FlagSrcDstBA != 0 {
			flagsStr += " B-A"
		}

		if flags&FlagHostPSNAT != 0 {
			flagsStr += " host-psnat"
		}

		if flags&FlagSvcSelf != 0 {
			flagsStr += " svc-self"
		}

		if flags&FlagNPLoop != 0 {
			flagsStr += " np-loop"
		}

		if flags&FlagNPRemote != 0 {
			flagsStr += " np-remote"
		}

		if flags&FlagNPRemote != 0 {
			flagsStr += " no-dsr"
		}
	}

	ret := fmt.Sprintf("Entry{Type:%d, LastSeen:%d, Flags:%s ",
		e.Type(), e.LastSeen(), flagsStr)

	switch e.Type() {
	case TypeNATForward:
		ret += fmt.Sprintf("REVKey: %s NATSPort: %d", e.ReverseNATKey().String(), e.NATSPort())
	case TypeNormal, TypeNATReverse:
		ret += fmt.Sprintf("Data: %+v", e.Data())
	default:
		ret += "TYPE INVALID"
	}

	return ret + "}"
}

func (e ValueV6) IsForwardDSR() bool {
	return e.Flags()&FlagNATFwdDsr != 0
}

func (e ValueV6) Upgrade() maps.Upgradable {
	panic("conntrack map value already at its latest version")
}

var MapParamsV6 = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeyV6Size,
	ValueSize:    ValueV6Size,
	MaxEntries:   MaxEntries,
	Name:         "cali_v6_ct",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      3,
	UpdatedByBPF: true,
}

func KeyV6FromBytes(k []byte) KeyInterface {
	var ctKey KeyV6
	if len(k) != len(ctKey) {
		log.Panic("KeyV6 has unexpected length")
	}
	copy(ctKey[:], k[:])
	return ctKey
}

func ValueV6FromBytes(v []byte) ValueInterface {
	var ctVal ValueV6
	if len(v) != len(ctVal) {
		log.Panic("ValueV6 has unexpected length")
	}
	copy(ctVal[:], v[:])
	return ctVal
}

type MapMemV6 map[KeyV6]ValueV6

// LoadMapMem loads ConntrackMap into memory
func LoadMapMemV6(m maps.Map) (MapMemV6, error) {
	ret := make(MapMemV6)

	err := m.Iter(func(k, v []byte) maps.IteratorAction {
		ks := len(KeyV6{})
		vs := len(ValueV6{})

		var key KeyV6
		copy(key[:ks], k[:ks])

		var val ValueV6
		copy(val[:vs], v[:vs])

		ret[key] = val
		return maps.IterNone
	})

	return ret, err
}

// MapMemIterV6 returns maps.MapIter that loads the provided MapMemV6
func MapMemIterV6(m MapMemV6) func(k, v []byte) {
	ks := len(KeyV6{})
	vs := len(ValueV6{})

	return func(k, v []byte) {
		var key KeyV6
		copy(key[:ks], k[:ks])

		var val ValueV6
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
