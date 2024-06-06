// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package routes

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
)

const KeyV6Size = 20

type KeyV6 [KeyV6Size]byte

func (k KeyV6) Addr() ip.Addr {
	var addr ip.V6Addr
	copy(addr[:], k[4:20])
	return addr
}

func (k KeyV6) Dest() ip.CIDR {
	addr := k.Addr()
	return ip.CIDRFromAddrAndPrefix(addr, k.PrefixLen())
}

func (k KeyV6) PrefixLen() int {
	return int(binary.LittleEndian.Uint32(k[:4]))
}

func (k KeyV6) AsBytes() []byte {
	return k[:]
}

const ValueV6Size = 20

type ValueV6 [ValueV6Size]byte

func (v ValueV6) Flags() Flags {
	return Flags(binary.LittleEndian.Uint32(v[:4]))
}

func (v ValueV6) NextHop() ip.Addr {
	var addr ip.V6Addr
	copy(addr[:], v[4:20])
	return addr
}

func (v ValueV6) IfaceIndex() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v ValueV6) AsBytes() []byte {
	return v[:]
}

func (v ValueV6) String() string {
	var parts []string

	typeFlags := v.Flags()

	if typeFlags&FlagLocal != 0 {
		parts = append(parts, "local")
	} else if typeFlags&FlagBlackHoleDrop == 0 && typeFlags&FlagBlackHoleReject == 0 {
		parts = append(parts, "remote")
	}

	if typeFlags&FlagHost != 0 {
		parts = append(parts, "host")
	} else if typeFlags&FlagWorkload != 0 {
		parts = append(parts, "workload")
	}

	if typeFlags&FlagInIPAMPool != 0 {
		parts = append(parts, "in-pool")
	}

	if typeFlags&FlagNATOutgoing != 0 {
		parts = append(parts, "nat-out")
	}

	if typeFlags&FlagSameSubnet != 0 {
		parts = append(parts, "same-subnet")
	}

	if typeFlags&FlagNoDSR != 0 {
		parts = append(parts, "no-dsr")
	}

	if typeFlags&FlagTunneled != 0 {
		parts = append(parts, "tunneled")
	}

	if typeFlags&FlagBlackHoleDrop != 0 {
		parts = append(parts, "blackhole-drop")
	}

	if typeFlags&FlagBlackHoleReject != 0 {
		parts = append(parts, "blackhole-reject")
	}

	if typeFlags&FlagLocal != 0 && typeFlags&FlagWorkload != 0 {
		parts = append(parts, "idx", fmt.Sprint(v.IfaceIndex()))
	}

	if typeFlags&FlagLocal == 0 && typeFlags&FlagWorkload != 0 {
		parts = append(parts, "nh", fmt.Sprint(v.NextHop()))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("unknown type (%d)", typeFlags)
	}

	return strings.Join(parts, " ")
}

func (v ValueV6) Equal(x ValueInterface) bool {
	X, ok := x.(ValueV6)
	return ok && v == X
}

func NewKeyV6(cidr ip.CIDR) KeyV6 {
	var k KeyV6

	binary.LittleEndian.PutUint32(k[:4], uint32(cidr.Prefix()))
	copy(k[4:20], cidr.Addr().AsNetIP().To16())

	return k
}

func NewValueV6(flags Flags) ValueV6 {
	var v ValueV6
	binary.LittleEndian.PutUint32(v[:4], uint32(flags))
	return v
}

func NewValueV6WithNextHop(flags Flags, nextHop ip.Addr) ValueV6 {
	var v ValueV6
	binary.LittleEndian.PutUint32(v[:4], uint32(flags))
	copy(v[4:20], nextHop.AsNetIP().To16())
	return v
}

func NewValueV6WithIfIndex(flags Flags, ifIndex int) ValueV6 {
	var v ValueV6
	binary.LittleEndian.PutUint32(v[:4], uint32(flags))
	binary.LittleEndian.PutUint32(v[4:8], uint32(ifIndex))
	return v
}

func NewKeyV6Intf(cidr ip.CIDR) KeyInterface {
	return NewKeyV6(cidr)
}

func NewValueV6Intf(flags Flags) ValueInterface {
	return NewValueV6(flags)
}

func NewValueV6IntfWithNextHop(flags Flags, nextHop ip.Addr) ValueInterface {
	return NewValueV6WithNextHop(flags, nextHop)
}

func NewValueV6IntfWithIfIndex(flags Flags, ifIndex int) ValueInterface {
	return NewValueV6WithIfIndex(flags, ifIndex)
}

func KeyV6InftFromBytes(b []byte) KeyInterface {
	var k KeyV6
	copy(k[:], b)
	return k
}

func ValueV6InftFromBytes(b []byte) ValueInterface {
	var v ValueV6
	copy(v[:], b)
	return v
}

var MapV6Parameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    KeyV6Size,
	ValueSize:  ValueV6Size,
	MaxEntries: 256 * 1024,
	Name:       "cali_v6_routes",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func MapV6() maps.Map {
	return maps.NewPinnedMap(MapV6Parameters)
}

type MapMemV6 map[KeyV6]ValueV6

// LoadMap loads a routes.Map into memory
func LoadMapV6(rtm maps.Map) (MapMemV6, error) {
	m := make(MapMemV6)

	err := rtm.Iter(func(k, v []byte) maps.IteratorAction {
		var key KeyV6
		var value ValueV6
		copy(key[:], k)
		copy(value[:], v)

		m[key] = value
		return maps.IterNone
	})

	return m, err
}
