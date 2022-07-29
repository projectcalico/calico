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

package conntrack

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap/upgrade"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"

	// When adding a new ct version, change curVer to point to the new version
	curVer "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
)

const KeySize = curVer.KeySize
const ValueSize = curVer.ValueSize
const MaxEntries = curVer.MaxEntries

type Key = curVer.Key

func NewKey(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) Key {
	return curVer.NewKey(proto, ipA, portA, ipB, portB)
}

type Value = curVer.Value

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

// NewValueNormal creates a new Value of type TypeNormal based on the given parameters
func NewValueNormal(created, lastSeen time.Duration, flags uint16, legA, legB Leg) Value {
	return curVer.NewValueNormal(created, lastSeen, flags, legA, legB)
}

// NewValueNATForward creates a new Value of type TypeNATForward for the given
// arguments and the reverse key
func NewValueNATForward(created, lastSeen time.Duration, flags uint16, revKey Key) Value {
	return curVer.NewValueNATForward(created, lastSeen, flags, revKey)
}

// NewValueNATReverse creates a new Value of type TypeNATReverse for the given
// arguments and reverse parameters
func NewValueNATReverse(created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP net.IP, origPort uint16) Value {
	return curVer.NewValueNATReverse(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origPort)
}

// NewValueNATReverseSNAT in addition to NewValueNATReverse sets the orig source IP
func NewValueNATReverseSNAT(created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP, origSrcIP net.IP, origPort uint16) Value {
	return curVer.NewValueNATReverseSNAT(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origSrcIP, origPort)
}

type Leg = curVer.Leg

var MapParams = curVer.MapParams

func Map(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(MapParams)
	b.(*bpf.PinnedMap).UpgradeFn = upgrade.UpgradeBPFMap
	b.(*bpf.PinnedMap).GetMapParams = GetMapParams
	b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
	return b
}

func MapV2(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(v2.MapParams)
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

type MapMem = curVer.MapMem

// LoadMapMem loads ConntrackMap into memory
func LoadMapMem(m bpf.Map) (MapMem, error) {
	ret, err := curVer.LoadMapMem(m)
	return ret, err
}

// MapMemIter returns bpf.MapIter that loads the provided MapMem
func MapMemIter(m MapMem) bpf.IterCallback {
	return curVer.MapMemIter(m)
}

// BytesToKey turns a slice of bytes into a Key
func BytesToKey(bytes []byte) Key {
	var k Key

	copy(k[:], bytes[:])

	return k
}

// StringToKey turns a string into a Key
func StringToKey(str string) Key {
	return BytesToKey([]byte(str))
}

// BytesToValue turns a slice of bytes into a value
func BytesToValue(bytes []byte) Value {
	var v Value

	copy(v[:], bytes)

	return v
}

// StringToValue turns a string into a Value
func StringToValue(str string) Value {
	return BytesToValue([]byte(str))
}

func GetMapParams(version int) bpf.MapParameters {
	switch version {
	case 2:
		return v2.MapParams
	case 3:
		return curVer.MapParams
	default:
		return curVer.MapParams
	}
}

func GetKeyValueTypeFromVersion(version int, k, v []byte) (bpf.Upgradable, bpf.Upgradable) {
	switch version {
	case 2:
		var key v2.Key
		var val v2.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	case 3:
		var key curVer.Key
		var val curVer.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	default:
		var key curVer.Key
		var val curVer.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	}
}
