// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
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
	"sync"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
)

func init() {
	SetMapSize(MapParameters.MaxEntries)
}

func SetMapSize(size int) {
	maps.SetSize(MapParameters.VersionedName(), size)
	maps.SetSize(MapV6Parameters.VersionedName(), size)
}

// struct cali_rt_key {
// __u32 mask;
// __be32 addr; // NBO
// };
const KeySize = 8

type Key [KeySize]byte

type KeyInterface interface {
	Addr() ip.Addr
	Dest() ip.CIDR
	PrefixLen() int
}

func (k Key) Addr() ip.Addr {
	var addr ip.V4Addr
	copy(addr[:], k[4:8])
	return addr
}

func (k Key) Dest() ip.CIDR {
	addr := k.Addr()
	return ip.CIDRFromAddrAndPrefix(addr, k.PrefixLen())
}

func (k Key) PrefixLen() int {
	return int(binary.LittleEndian.Uint32(k[:4]))
}

func (k Key) AsBytes() []byte {
	return k[:]
}

type Flags uint32

const (
	FlagInIPAMPool  Flags = 0x01
	FlagNATOutgoing Flags = 0x02
	FlagWorkload    Flags = 0x04
	FlagLocal       Flags = 0x08
	FlagHost        Flags = 0x10
	FlagSameSubnet  Flags = 0x20
	FlagTunneled    Flags = 0x40
	FlagNoDSR       Flags = 0x80

	FlagsUnknown            Flags = 0
	FlagsRemoteWorkload           = FlagWorkload
	FlagsRemoteHost               = FlagHost
	FlagsLocalHost                = FlagLocal | FlagHost
	FlagsLocalWorkload            = FlagLocal | FlagWorkload
	FlagsRemoteTunneledHost       = FlagsRemoteHost | FlagTunneled
	FlagsLocalTunneledHost        = FlagsLocalHost | FlagTunneled

	_ = FlagsUnknown
)

//	struct cali_rt_value {
//	  __u32 flags;
//	  union {
//	    __u32 next_hop;
//	    __u32 ifIndex;
//	  };
//	};
const ValueSize = 8

type Value [ValueSize]byte

type ValueInterface interface {
	Flags() Flags
	NextHop() ip.Addr
	IfaceIndex() uint32
}

func (v Value) Flags() Flags {
	return Flags(binary.LittleEndian.Uint32(v[:4]))
}

func (v Value) NextHop() ip.Addr {
	var addr ip.V4Addr
	copy(addr[:], v[4:8])
	return addr
}

func (v Value) IfaceIndex() uint32 {
	return binary.LittleEndian.Uint32(v[4:8])
}

func (v Value) AsBytes() []byte {
	return v[:]
}

func (v Value) String() string {
	var parts []string

	typeFlags := v.Flags()

	if typeFlags&FlagLocal != 0 {
		parts = append(parts, "local")
	} else {
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

func NewKey(cidr ip.V4CIDR) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:4], uint32(cidr.Prefix()))
	copy(k[4:8], cidr.Addr().AsNetIP().To4())

	return k
}

func NewValue(flags Flags) Value {
	var v Value
	binary.LittleEndian.PutUint32(v[:4], uint32(flags))
	return v
}

func NewValueWithNextHop(flags Flags, nextHop ip.V4Addr) Value {
	var v Value
	binary.LittleEndian.PutUint32(v[:4], uint32(flags))
	copy(v[4:8], nextHop.AsNetIP().To4())
	return v
}

func NewValueWithIfIndex(flags Flags, ifIndex int) Value {
	var v Value
	binary.LittleEndian.PutUint32(v[:4], uint32(flags))
	binary.LittleEndian.PutUint32(v[4:8], uint32(ifIndex))
	return v
}

var MapParameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 256 * 1024,
	Name:       "cali_v4_routes",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParameters)
}

type MapMem map[Key]Value

// LoadMap loads a routes.Map into memory
func LoadMap(rtm maps.Map) (MapMem, error) {
	m := make(MapMem)

	err := rtm.Iter(func(k, v []byte) maps.IteratorAction {
		var key Key
		var value Value
		copy(key[:], k)
		copy(value[:], v)

		m[key] = value
		return maps.IterNone
	})

	return m, err
}

type LPM struct {
	sync.RWMutex
	t *ip.CIDRTrie
}

func NewLPM() *LPM {
	return &LPM{
		t: ip.NewCIDRTrie(),
	}
}

func (lpm *LPM) Update(k KeyInterface, v ValueInterface) {
	lpm.t.Update(k.Dest(), v)
}

func (lpm *LPM) Delete(k KeyInterface) {
	lpm.t.Delete(k.Dest())
}

func (lpm *LPM) Lookup(addr ip.Addr) (ValueInterface, bool) {
	_, v := lpm.t.LPM(addr.AsCIDR())
	if v == nil {
		return nil, false
	}
	return v.(ValueInterface), true
}
