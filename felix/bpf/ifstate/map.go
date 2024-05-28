// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package ifstate

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

func init() {
	SetMapSize(MapParams.MaxEntries)
}

func SetMapSize(size int) {
	maps.SetSize(MapParams.VersionedName(), size)
}

const (
	KeySize    = 4
	ValueSize  = 4 + 16 + 3*4 + 3*4 + 2*4
	MaxEntries = 1000
)

const (
	FlgWEP       = uint32(0x1)
	FlgIPv4Ready = uint32(0x2)
	FlgIPv6Ready = uint32(0x4)
	FlgHEP       = uint32(0x8)
	FlgBond      = uint32(0x10)
	FlgBondSlave = uint32(0x20)
	FlgVxlan     = uint32(0x40)
	FlgIPIP      = uint32(0x80)
	FlgWireguard = uint32(0x100)
	FlgL3        = uint32(0x200)
	FlgMax       = uint32(0x3ff)
)

var flagsToStr = map[uint32]string{
	FlgWEP:       "workload",
	FlgIPv4Ready: "v4Ready",
	FlgIPv6Ready: "v6Ready",
	FlgHEP:       "host",
	FlgBond:      "bond",
	FlgBondSlave: "bondslave",
	FlgVxlan:     "vxlan",
	FlgIPIP:      "ipip",
	FlgWireguard: "wg",
	FlgL3:        "l3",
}

var MapParams = maps.MapParameters{
	Type:         "hash",
	KeySize:      KeySize,
	ValueSize:    ValueSize,
	MaxEntries:   MaxEntries,
	Name:         "cali_iface",
	Flags:        unix.BPF_F_NO_PREALLOC,
	Version:      4,
	UpdatedByBPF: false,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParams)
}

type Key [4]byte

func NewKey(ifIndex uint32) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:], ifIndex)

	return k
}

func (k Key) AsBytes() []byte {
	return k[:]
}

func (k Key) IfIndex() uint32 {
	return binary.LittleEndian.Uint32(k[:])
}

func (k Key) String() string {
	return fmt.Sprintf("{ifIndex: %d}", k.IfIndex())
}

func KeyFromBytes(b []byte) Key {
	var k Key
	copy(k[:], b)
	return k
}

type Value [ValueSize]byte

func NewValue(
	flags uint32,
	name string,
	xdpPolIPv4,
	ingressPolIPv4,
	egressPolIPv4,
	xdpPolIPv6,
	ingressPolIPv6,
	egressPolIPv6,
	tcIngressFilter,
	tcEgressFilter int,
) Value {
	var v Value

	binary.LittleEndian.PutUint32(v[:], flags)
	copy(v[4:4+15], []byte(name))
	binary.LittleEndian.PutUint32(v[4+16+0:4+16+4], uint32(xdpPolIPv4))
	binary.LittleEndian.PutUint32(v[4+16+4:4+16+8], uint32(ingressPolIPv4))
	binary.LittleEndian.PutUint32(v[4+16+8:4+16+12], uint32(egressPolIPv4))
	binary.LittleEndian.PutUint32(v[4+16+12:4+16+16], uint32(xdpPolIPv6))
	binary.LittleEndian.PutUint32(v[4+16+16:4+16+20], uint32(ingressPolIPv6))
	binary.LittleEndian.PutUint32(v[4+16+20:4+16+24], uint32(egressPolIPv6))
	binary.LittleEndian.PutUint32(v[4+16+24:4+16+28], uint32(tcIngressFilter))
	binary.LittleEndian.PutUint32(v[4+16+28:4+16+32], uint32(tcEgressFilter))

	return v
}

func (v Value) AsBytes() []byte {
	return v[:]
}

func (v Value) Flags() uint32 {
	return binary.LittleEndian.Uint32(v[:])
}

func (v Value) IfName() string {
	return strings.TrimRight(string(v[4:4+16]), "\x00")
}

func (v Value) XDPPolicyV4() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16 : 4+16+4])))
}

func (v Value) IngressPolicyV4() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+4 : 4+16+8])))
}

func (v Value) EgressPolicyV4() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+8 : 4+16+12])))
}

func (v Value) XDPPolicyV6() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+12 : 4+16+16])))
}

func (v Value) IngressPolicyV6() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+16 : 4+16+20])))
}

func (v Value) EgressPolicyV6() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+20 : 4+16+24])))
}

func (v Value) TcIngressFilter() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+24 : 4+16+28])))
}

func (v Value) TcEgressFilter() int {
	return int(int32(binary.LittleEndian.Uint32(v[4+16+28 : 4+16+32])))
}

func (v Value) String() string {
	fstr := ""
	f := v.Flags()

	for k := FlgWEP; k < FlgMax; k *= 2 {
		v := flagsToStr[k]
		if f&k != 0 {
			fstr = fstr + v + ","
		}
	}

	if fstr == "" {
		fstr = "host,"
	}

	return fmt.Sprintf(
		"{flags: %s XDPPolicyV4: %d, IngressPolicyV4: %d, EgressPolicyV4: %d, XDPPolicyV6: %d, IngressPolicyV6: %d, EgressPolicyV6: %d, IngressFilter: %d, EgressFilter: %d, name: %s}",
		fstr, v.XDPPolicyV4(), v.IngressPolicyV4(), v.EgressPolicyV4(), v.XDPPolicyV6(), v.IngressPolicyV6(), v.EgressPolicyV6(), v.TcIngressFilter(), v.TcEgressFilter(), v.IfName())
}

func ValueFromBytes(b []byte) Value {
	var v Value
	copy(v[:], b)
	return v
}

type MapMem map[Key]Value

func MapMemIter(m MapMem) func(k, v []byte) {
	ks := len(Key{})
	vs := len(Value{})

	return func(k, v []byte) {
		var key Key
		copy(key[:ks], k[:ks])

		var val Value
		copy(val[:vs], v[:vs])

		m[key] = val
	}
}
