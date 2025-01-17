//go:build !windows
// +build !windows

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

	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	"github.com/projectcalico/calico/felix/bpf/maps"

	// When adding a new ct version, change curVerXXX to point to the new version
	curVerCleanup "github.com/projectcalico/calico/felix/bpf/conntrack/cleanupv1"
	curVer "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
)

func init() {
	SetMapSize(MaxEntries)
}

func SetMapSize(size int) {
	maps.SetSize(curVer.MapParams.VersionedName(), size)
	maps.SetSize(curVer.MapParamsV6.VersionedName(), size)
}

func SetCleanupMapSize(size int) {
	maps.SetSize(curVerCleanup.MapParams.VersionedName(), size)
	maps.SetSize(curVerCleanup.MapParamsV6.VersionedName(), size)
}

const KeySize = curVer.KeySize
const KeyV6Size = curVer.KeyV6Size
const ValueSize = curVer.ValueSize
const ValueV6Size = curVer.ValueV6Size
const MaxEntries = curVer.MaxEntries

type Key = curVer.Key
type KeyV6 = curVer.KeyV6
type KeyInterface = curVer.KeyInterface

func NewKey(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) Key {
	return curVer.NewKey(proto, ipA, portA, ipB, portB)
}

func NewKeyV6(proto uint8, ipA net.IP, portA uint16, ipB net.IP, portB uint16) KeyV6 {
	return curVer.NewKeyV6(proto, ipA, portA, ipB, portB)
}

type Value = curVer.Value
type ValueV6 = curVer.ValueV6
type ValueInterface = curVer.ValueInterface

const (
	TypeNormal uint8 = iota
	TypeNATForward
	TypeNATReverse
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
func NewValueNATReverse(
	created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP net.IP, origPort uint16,
) Value {
	return curVer.NewValueNATReverse(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origPort)
}

// NewValueNATReverseSNAT in addition to NewValueNATReverse sets the orig source IP
func NewValueNATReverseSNAT(
	created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP, origSrcIP net.IP, origPort uint16,
) Value {
	return curVer.NewValueNATReverseSNAT(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origSrcIP, origPort)
}

// NewValueV6Normal creates a new ValueV6 of type TypeNormal based on the given parameters
func NewValueV6Normal(created, lastSeen time.Duration, flags uint16, legA, legB Leg) ValueV6 {
	return curVer.NewValueV6Normal(created, lastSeen, flags, legA, legB)
}

// NewValueV6NATForward creates a new ValueV6 of type TypeNATForward for the given
// arguments and the reverse key
func NewValueV6NATForward(created, lastSeen time.Duration, flags uint16, revKey KeyV6) ValueV6 {
	return curVer.NewValueV6NATForward(created, lastSeen, flags, revKey)
}

// NewValueV6NATReverse creates a new ValueV6 of type TypeNATReverse for the given
// arguments and reverse parameters
func NewValueV6NATReverse(
	created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP net.IP, origPort uint16,
) ValueV6 {
	return curVer.NewValueV6NATReverse(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origPort)
}

// NewValueV6NATReverseSNAT in addition to NewValueV6NATReverse sets the orig source IP
func NewValueV6NATReverseSNAT(
	created, lastSeen time.Duration, flags uint16, legA, legB Leg,
	tunnelIP, origIP, origSrcIP net.IP, origPort uint16,
) ValueV6 {
	return curVer.NewValueV6NATReverseSNAT(created, lastSeen, flags, legA, legB, tunnelIP, origIP, origSrcIP, origPort)
}

type Leg = curVer.Leg

var MapParams = curVer.MapParams
var MapParamsV6 = curVer.MapParamsV6

func Map() maps.Map {
	b := maps.NewPinnedMap(MapParams)
	b.UpgradeFn = maps.Upgrade
	b.GetMapParams = GetMapParams
	b.KVasUpgradable = GetKeyValueTypeFromVersion
	return b
}

func MapV6() maps.Map {
	b := maps.NewPinnedMap(MapParamsV6)
	b.GetMapParams = GetMapParams
	return b
}

func MapV2() maps.Map {
	return maps.NewPinnedMap(v2.MapParams)
}

const (
	ProtoICMP  = 1
	ProtoTCP   = 6
	ProtoUDP   = 17
	ProtoICMP6 = 58
)

func KeyFromBytes(k []byte) KeyInterface {
	var ctKey Key
	if len(k) != len(ctKey) {
		log.Panic("Key has unexpected length")
	}
	copy(ctKey[:], k[:])
	return ctKey
}

func ValueFromBytes(v []byte) ValueInterface {
	var ctVal Value
	if len(v) != len(ctVal) {
		log.Panic("Value has unexpected length")
	}
	copy(ctVal[:], v[:])
	return ctVal
}

type MapMem = curVer.MapMem

// LoadMapMem loads ConntrackMap into memory
func LoadMapMem(m maps.Map) (MapMem, error) {
	ret, err := curVer.LoadMapMem(m)
	return ret, err
}

// MapMemIter returns maps.MapIter that loads the provided MapMem
func MapMemIter(m MapMem) func(k, v []byte) {
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

func KeyV6FromBytes(k []byte) KeyInterface {
	var ctKeyV6 KeyV6
	if len(k) != len(ctKeyV6) {
		log.Panic("KeyV6 has unexpected length")
	}
	copy(ctKeyV6[:], k[:])
	return ctKeyV6
}

func ValueV6FromBytes(v []byte) ValueInterface {
	var ctVal ValueV6
	if len(v) != len(ctVal) {
		log.Panic("ValueV6 has unexpected length")
	}
	copy(ctVal[:], v[:])
	return ctVal
}

type MapMemV6 = curVer.MapMemV6

// LoadMapMem loads ConntrackMap into memory
func LoadMapMemV6(m maps.Map) (MapMemV6, error) {
	ret, err := curVer.LoadMapMemV6(m)
	return ret, err
}

// MapMemIter returns maps.MapIter that loads the provided MapMem
func MapMemIterV6(m MapMemV6) func(k, v []byte) {
	return curVer.MapMemIterV6(m)
}

// BytesToKeyV6 turns a slice of bytes into a KeyV6
func BytesToKeyV6(bytes []byte) KeyV6 {
	var k KeyV6

	copy(k[:], bytes[:])

	return k
}

// StringToKeyV6 turns a string into a KeyV6
func StringToKeyV6(str string) KeyV6 {
	return BytesToKeyV6([]byte(str))
}

// BytesToValueV6 turns a slice of bytes into a value
func BytesToValueV6(bytes []byte) ValueV6 {
	var v ValueV6

	copy(v[:], bytes)

	return v
}

// StringToValueV6 turns a string into a ValueV6
func StringToValueV6(str string) ValueV6 {
	return BytesToValueV6([]byte(str))
}

func GetMapParams(version int) maps.MapParameters {
	switch version {
	case 2:
		return v2.MapParams
	case 3:
		return curVer.MapParams
	default:
		return curVer.MapParams
	}
}

func GetKeyValueTypeFromVersion(version int, k, v []byte) (maps.Upgradable, maps.Upgradable) {
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
