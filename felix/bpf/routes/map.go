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

package routes

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/ip"
)

//
// struct cali_rt_key {
// __u32 mask;
// __be32 addr; // NBO
// };
const KeySize = 8

type Key [KeySize]byte

func (k Key) Addr() ip.Addr {
	var addr ip.V4Addr // FIXME IPv6
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

	FlagsUnknown        Flags = 0
	FlagsRemoteWorkload       = FlagWorkload
	FlagsRemoteHost           = FlagHost
	FlagsLocalHost            = FlagLocal | FlagHost
	FlagsLocalWorkload        = FlagLocal | FlagWorkload

	_ = FlagsUnknown
)

//
// struct cali_rt_value {
//   __u32 flags;
//   union {
//     __u32 next_hop;
//     __u32 ifIndex;
//   };
// };
const ValueSize = 8

type Value [ValueSize]byte

func (v Value) Flags() Flags {
	return Flags(binary.LittleEndian.Uint32(v[:4]))
}

func (v Value) NextHop() ip.Addr {
	var addr ip.V4Addr // FIXME IPv6
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

var MapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_routes",
	Type:       "lpm_trie",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 256 * 1024,
	Name:       "cali_v4_routes",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParameters)
}

type MapMem map[Key]Value

// LoadMap loads a routes.Map into memory
func LoadMap(rtm bpf.Map) (MapMem, error) {
	m := make(MapMem)

	err := rtm.Iter(func(k, v []byte) bpf.IteratorAction {
		var key Key
		var value Value
		copy(key[:], k)
		copy(value[:], v)

		m[key] = value
		return bpf.IterNone
	})

	return m, err
}

type LPMv4 struct {
	sync.RWMutex
	t *ip.V4Trie
}

func NewLPMv4() *LPMv4 {
	return &LPMv4{
		t: new(ip.V4Trie),
	}
}

func (lpm *LPMv4) Update(k Key, v Value) error {
	if cidrv4, ok := k.Dest().(ip.V4CIDR); ok {
		lpm.t.Update(cidrv4, v)
		return nil
	}

	return errors.Errorf("k.Dest() %+v type %T is not ip.V4CIDR", k.Dest(), k.Dest())
}

func (lpm *LPMv4) Delete(k Key) error {
	if cidrv4, ok := k.Dest().(ip.V4CIDR); ok {
		lpm.t.Delete(cidrv4)
		return nil
	}

	return errors.Errorf("k.Dest() %+v type %T is not ip.V4CIDR", k.Dest(), k.Dest())
}

func (lpm *LPMv4) Lookup(addr ip.V4Addr) (Value, bool) {
	_, v := lpm.t.LPM(addr.AsCIDR().(ip.V4CIDR))
	if v == nil {
		return Value{}, false
	}
	return v.(Value), true
}
