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

	"github.com/projectcalico/calico/felix/bpf"
)

//	struct calico_ct_key {
//	  uint32_t protocol;
//	  __be32 addr_a, addr_b; // NBO
//	  uint16_t port_a, port_b; // HBO
//	};
const KeySize = 16
const ValueSize = 88
const MaxEntries = 512000

type Key [KeySize]byte

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

func (k Key) Upgrade() bpf.Upgradable {
	panic("conntrack map key already at its latest version")
}

func NewKey(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) Key {
	var k Key
	binary.LittleEndian.PutUint32(k[:4], uint32(proto))
	copy(k[4:8], ipA.To4())
	copy(k[8:12], ipB.To4())
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
	VoCreated   int = 0
	VoLastSeen  int = 8
	VoType      int = 16
	VoFlags     int = 17
	VoFlags2    int = 23
	VoRevKey    int = 24
	VoLegAB     int = 24
	VoLegBA     int = 48
	VoOrigIP    int = 76
	VoOrigPort  int = 80
	VoOrigSPort int = 82
	VoOrigSIP   int = 84
	VoTunIP     int = 72
	VoNATSPort  int = 40
)

type Value [ValueSize]byte

func (e Value) Created() int64 {
	return int64(binary.LittleEndian.Uint64(e[VoCreated : VoCreated+8]))
}

func (e Value) LastSeen() int64 {
	return int64(binary.LittleEndian.Uint64(e[VoLastSeen : VoLastSeen+8]))
}

func (e Value) Type() uint8 {
	return e[VoType]
}

func (e Value) Flags() uint16 {
	return uint16(e[VoFlags]) | (uint16(e[VoFlags2]) << 8)
}

// OrigIP returns the original destination IP, valid only if Type() is TypeNormal or TypeNATReverse
func (e Value) OrigIP() net.IP {
	return e[VoOrigIP : VoOrigIP+4]
}

// OrigPort returns the original destination port, valid only if Type() is TypeNormal or TypeNATReverse
func (e Value) OrigPort() uint16 {
	return binary.LittleEndian.Uint16(e[VoOrigPort : VoOrigPort+2])
}

// OrigSPort returns the original source port, valid only if Type() is
// TypeNATReverse and if the value returned is non-zero.
func (e Value) OrigSPort() uint16 {
	return binary.LittleEndian.Uint16(e[VoOrigSPort : VoOrigSPort+2])
}

// NATSPort returns the port to SNAT to, valid only if Type() is TypeNATForward.
func (e Value) NATSPort() uint16 {
	return binary.LittleEndian.Uint16(e[VoNATSPort : VoNATSPort+2])
}

// OrigSrcIP returns the original source IP.
func (e Value) OrigSrcIP() net.IP {
	return e[VoOrigSIP : VoOrigSIP+4]
}

const (
	TypeNormal uint8 = iota
	TypeNATForward
	TypeNATReverse

	FlagNATOut    uint16 = (1 << 0)
	FlagNATFwdDsr uint16 = (1 << 1)
	FlagNATNPFwd  uint16 = (1 << 2)
	FlagSkipFIB   uint16 = (1 << 3)
	FlagReserved4 uint16 = (1 << 4)
	FlagReserved5 uint16 = (1 << 5)
	FlagExtLocal  uint16 = (1 << 6)
	FlagViaNATIf  uint16 = (1 << 7)
	FlagSrcDstBA  uint16 = (1 << 8)
)

func (e Value) ReverseNATKey() Key {
	var ret Key

	l := len(Key{})
	copy(ret[:l], e[VoRevKey:VoRevKey+l])

	return ret
}

// AsBytes returns the value as slice of bytes
func (e Value) AsBytes() []byte {
	return e[:]
}

func (e *Value) SetLegA2B(leg Leg) {
	copy(e[VoLegAB:VoLegAB+legSize], leg.AsBytes())
}

func (e *Value) SetLegB2A(leg Leg) {
	copy(e[VoLegBA:VoLegBA+legSize], leg.AsBytes())
}

func (e *Value) SetOrigSport(sport uint16) {
	binary.LittleEndian.PutUint16(e[VoOrigSPort:VoOrigSPort+2], sport)
}

func (e *Value) SetNATSport(sport uint16) {
	binary.LittleEndian.PutUint16(e[VoNATSPort:VoNATSPort+2], sport)
}

func initValue(v *Value, created, lastSeen time.Duration, typ uint8, flags uint16) {
	binary.LittleEndian.PutUint64(v[VoCreated:VoCreated+8], uint64(created))
	binary.LittleEndian.PutUint64(v[VoLastSeen:VoLastSeen+8], uint64(lastSeen))
	v[VoType] = typ
	v[VoFlags] = byte(flags & 0xff)
	v[VoFlags2] = byte((flags >> 8) & 0xff)
}

// NewValueNormal creates a new Value of type TypeNormal based on the given parameters
func NewValueNormal(created, lastSeen time.Duration, flags uint16, legA, legB Leg) Value {
	v := Value{}

	initValue(&v, created, lastSeen, TypeNormal, flags)

	v.SetLegA2B(legA)
	v.SetLegB2A(legB)

	return v
}

// NewValueNATForward creates a new Value of type TypeNATForward for the given
// arguments and the reverse key
func NewValueNATForward(created, lastSeen time.Duration, flags uint16, revKey Key) Value {
	v := Value{}

	initValue(&v, created, lastSeen, TypeNATForward, flags)

	copy(v[VoRevKey:VoRevKey+KeySize], revKey.AsBytes())

	return v
}

// NewValueNATReverse creates a new Value of type TypeNATReverse for the given
// arguments and reverse parameters
func NewValueNATReverse(created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP net.IP, origPort uint16) Value {
	v := Value{}

	initValue(&v, created, lastSeen, TypeNATReverse, flags)

	v.SetLegA2B(legA)
	v.SetLegB2A(legB)

	copy(v[VoOrigIP:VoOrigIP+4], origIP.To4())
	binary.LittleEndian.PutUint16(v[VoOrigPort:VoOrigPort+2], origPort)

	copy(v[VoTunIP:VoTunIP+4], tunnelIP.To4())

	return v
}

// NewValueNATReverseSNAT in addition to NewValueNATReverse sets the orig source IP
func NewValueNATReverseSNAT(created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP, origSrcIP net.IP, origPort uint16) Value {
	v := NewValueNATReverse(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origPort)
	copy(v[VoOrigSIP:VoOrigSIP+4], origIP.To4())

	return v
}

type Leg struct {
	Bytes       uint64
	Packets     uint32
	Seqno       uint32
	SynSeen     bool
	AckSeen     bool
	FinSeen     bool
	RstSeen     bool
	Whitelisted bool
	Opener      bool
	Ifindex     uint32
}

const legSize int = 24

func setBit(bits *uint32, bit uint8, val bool) {
	if val {
		*bits |= (1 << bit)
	}
}

const legExtra = 12

// AsBytes returns Leg serialized as a slice of bytes
func (leg Leg) AsBytes() []byte {
	bytes := make([]byte, legSize)

	bits := uint32(0)

	setBit(&bits, 0, leg.SynSeen)
	setBit(&bits, 1, leg.AckSeen)
	setBit(&bits, 2, leg.FinSeen)
	setBit(&bits, 3, leg.RstSeen)
	setBit(&bits, 4, leg.Whitelisted)
	setBit(&bits, 5, leg.Opener)

	binary.LittleEndian.PutUint64(bytes[0:8], leg.Bytes)
	binary.LittleEndian.PutUint32(bytes[8:12], leg.Packets)
	binary.LittleEndian.PutUint32(bytes[legExtra+0:legExtra+4], leg.Seqno)
	binary.LittleEndian.PutUint32(bytes[legExtra+4:legExtra+8], bits)
	binary.LittleEndian.PutUint32(bytes[legExtra+8:legExtra+12], leg.Ifindex)

	return bytes
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
	bits := binary.LittleEndian.Uint32(b[legExtra+4 : legExtra+8])
	return Leg{
		Bytes:       binary.LittleEndian.Uint64(b[0:8]),
		Packets:     binary.LittleEndian.Uint32(b[8:12]),
		Seqno:       binary.BigEndian.Uint32(b[legExtra+0 : legExtra+4]),
		SynSeen:     bitSet(bits, 0),
		AckSeen:     bitSet(bits, 1),
		FinSeen:     bitSet(bits, 2),
		RstSeen:     bitSet(bits, 3),
		Whitelisted: bitSet(bits, 4),
		Opener:      bitSet(bits, 5),
		Ifindex:     binary.LittleEndian.Uint32(b[legExtra+8 : legExtra+12]),
	}
}

type EntryData struct {
	A2B       Leg
	B2A       Leg
	OrigDst   net.IP
	OrigSrc   net.IP
	OrigPort  uint16
	OrigSPort uint16
	TunIP     net.IP
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
	ip := e[VoOrigIP : VoOrigIP+4]
	tip := e[VoTunIP : VoTunIP+4]
	sip := e[VoOrigSIP : VoOrigSIP+4]
	return EntryData{
		A2B:       readConntrackLeg(e[VoLegAB : VoLegAB+legSize]),
		B2A:       readConntrackLeg(e[VoLegBA : VoLegBA+legSize]),
		OrigDst:   ip,
		OrigSrc:   sip,
		OrigPort:  binary.LittleEndian.Uint16(e[VoOrigPort : VoOrigPort+2]),
		OrigSPort: binary.LittleEndian.Uint16(e[VoOrigPort+2 : VoOrigPort+4]),
		TunIP:     tip,
	}
}

func (e Value) String() string {
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
	}

	ret := fmt.Sprintf("Entry{Type:%d, Created:%d, LastSeen:%d, Flags:%s ",
		e.Type(), e.Created(), e.LastSeen(), flagsStr)

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

func (e Value) IsForwardDSR() bool {
	return e.Flags()&FlagNATFwdDsr != 0
}

func (e Value) Upgrade() bpf.Upgradable {
	panic("conntrack map value already at its latest version")
}

var MapParams = bpf.MapParameters{
	Filename:     "/sys/fs/bpf/tc/globals/cali_v4_ct",
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_v4_ct",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      3,
	UpdatedByBPF: true,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParams)
}

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

func KeyFromBytes(k []byte) Key {
	var ctKey Key
	if len(k) != len(ctKey) {
		log.Panic("Key has unexpected length")
	}
	copy(ctKey[:], k[:])
	return ctKey
}

func ValueFromBytes(v []byte) Value {
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
