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
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"

	// When adding a new ct version, change curVer to point to the new version
	"github.com/projectcalico/calico/felix/bpf/cachingmap"
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
type EntryData = curVer.EntryData

var MapParams = curVer.MapParams

type MultiVersionMap struct {
	CurVersion int
	ctMap      bpf.Map
	MapParams  []bpf.MapParameters
}

func (m *MultiVersionMap) GetName() string {
	return m.ctMap.GetName()
}

func (m *MultiVersionMap) Update(k, v []byte) error {
	return m.ctMap.Update(k, v)
}

func (m *MultiVersionMap) Get(k []byte) ([]byte, error) {
	return m.ctMap.Get(k)
}

func (m *MultiVersionMap) Delete(k []byte) error {
	return m.ctMap.Delete(k)
}

func (m *MultiVersionMap) Path() string {
	return m.ctMap.Path()
}

func (m *MultiVersionMap) CopyDeltaFromOldMap() error {
	return m.ctMap.CopyDeltaFromOldMap()
}

func (m *MultiVersionMap) Iter(f bpf.IterCallback) error {
	return m.ctMap.Iter(f)
}

func (m *MultiVersionMap) EnsureExists() error {
	err := m.ctMap.EnsureExists()
	if err != nil {
		return err
	}
	err = m.Upgrade()
	if err != nil {
		log.Debugf("error upgrading conntrack map, err=%s", err)
	}
	return nil
}

func (m *MultiVersionMap) Open() error {
	return m.ctMap.Open()
}

func (m *MultiVersionMap) MapFD() bpf.MapFD {
	return m.ctMap.MapFD()
}

func (m *MultiVersionMap) Close() {
	m.ctMap.(*bpf.PinnedMap).Close()
}

// Upgrade does the actual upgrade by iterating through the
// k,v pairs in the old map, applying the conversion functions
// and writing the new k,v pair to the newly created map.
func (m *MultiVersionMap) Upgrade() error {
	mc := &bpf.MapContext{}
	from := 0
	to := m.CurVersion
	err := getOldVersion(to, &from)
	if err != nil {
		return err
	} else if from == 0 {
		// It is a fresh install. Just return
		return nil
	}
	toBpfMap := m.ctMap
	toCachingMap := cachingmap.New(m.MapParams[to], toBpfMap)
	if toCachingMap == nil {
		return fmt.Errorf("error creating caching map")
	}
	err = toCachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}

	fromMapParams := m.MapParams[from]
	fromBpfMap := mc.NewPinnedMap(fromMapParams)
	err = fromBpfMap.EnsureExists()
	if err != nil {
		return fmt.Errorf("error creating a handle for the old map")
	}

	defer fromBpfMap.(*bpf.PinnedMap).Close()
	fromCachingMap := cachingmap.New(fromMapParams, fromBpfMap)
	if fromCachingMap == nil {
		return fmt.Errorf("error creating caching map")
	}
	err = fromCachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}
	fromCachingMap.IterDataplaneCache(func(k, v []byte) {
		tmpVal := v[:]
		tmpKey := k[:]
		for i := from; i < to; i++ {
			key := conversionKey{from: i, to: i + 1}
			f := conversionFns[key]
			tmpKey, tmpVal, err = f(tmpKey, tmpVal)
			if err != nil {
				err = fmt.Errorf("error upgrading conntrack map %w", err)
				break
			}
		}
		toCachingMap.SetDesired(tmpKey, tmpVal)
	})

	if err != nil {
		return err
	}

	err = toCachingMap.ApplyAllChanges()
	if err != nil {
		return fmt.Errorf("error upgrading new map %w", err)
	}
	return nil
}

// When adding a new ct map version, add an entry to the MapParams array
// and set the CurVersion to the new map version.
func Map(mc *bpf.MapContext) bpf.Map {
	return &MultiVersionMap{
		CurVersion: 3,
		MapParams:  []bpf.MapParameters{bpf.MapParameters{}, bpf.MapParameters{}, v2.MapParams, curVer.MapParams},
		ctMap:      mc.NewPinnedMap(curVer.MapParams),
	}
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
