// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package mock

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/mock/v2"
	"github.com/projectcalico/calico/felix/bpf/mock/v3"
	"github.com/projectcalico/calico/felix/bpf/mock/v4"
	"github.com/projectcalico/calico/felix/bpf/mock/v5"
)

type Map struct {
	bpf.MapParameters
	logCxt *logrus.Entry

	Contents map[string]string

	UpdateCount int
	GetCount    int
	DeleteCount int
	IterCount   int

	IterErr   error
	UpdateErr error
	DeleteErr error
}

func (m *Map) MapFD() bpf.MapFD {
	panic("implement me")
}

func (m *Map) Open() error {
	m.logCxt.Info("Open called")
	return nil
}

func (m *Map) EnsureExists() error {
	m.logCxt.Info("EnsureExists called")
	return nil
}

func (m *Map) GetName() string {
	return m.Name
}

func (m *Map) Path() string {
	return m.Filename
}

func (m *Map) Iter(f bpf.IterCallback) error {
	m.IterCount++

	if m.IterErr != nil {
		return m.IterErr
	}

	for kstr, vstr := range m.Contents {
		action := f([]byte(kstr), []byte(vstr))
		if action == bpf.IterDelete {
			delete(m.Contents, kstr)
		}
	}
	return nil
}

func (m *Map) Update(k, v []byte) error {
	m.UpdateCount++
	if m.UpdateErr != nil {
		return m.UpdateErr
	}

	if len(k) != m.KeySize {
		m.logCxt.Panicf("Key had wrong size (%d)", len(k))
	}
	if len(v) != m.ValueSize {
		m.logCxt.Panicf("Value had wrong size (%d)", len(v))
	}
	m.Contents[string(k)] = string(v)

	return nil
}

func (m *Map) Get(k []byte) ([]byte, error) {
	m.GetCount++

	vstr, ok := m.Contents[string(k)]
	if !ok {
		return nil, unix.ENOENT
	}
	return []byte(vstr), nil
}

func (m *Map) Delete(k []byte) error {
	m.DeleteCount++
	if m.DeleteErr != nil {
		return m.DeleteErr
	}

	if len(k) != m.KeySize {
		m.logCxt.Panicf("Key had wrong size (%d)", len(k))
	}
	delete(m.Contents, string(k))
	return nil
}

func (m *Map) OpCount() int {
	return m.UpdateCount + m.IterCount + m.GetCount + m.DeleteCount
}

func (m *Map) CopyDeltaFromOldMap() error {
	return nil
}

func NewMockMap(params bpf.MapParameters) *Map {
	if params.KeySize <= 0 {
		logrus.WithField("params", params).Panic("KeySize should be >0")
	}
	if params.ValueSize <= 0 {
		logrus.WithField("params", params).Panic("ValueSize should be >0")
	}
	m := &Map{
		MapParameters: params,
		logCxt: logrus.WithFields(logrus.Fields{
			"name":      params.Name,
			"mapType":   params.Type,
			"keySize":   params.KeySize,
			"valueSize": params.ValueSize,
		}),
		Contents: map[string]string{},
	}
	return m
}

var _ bpf.Map = (*Map)(nil)

type DummyMap struct{}

func (*DummyMap) GetName() string {
	return "DummyMap"
}

func (*DummyMap) Open() error {
	return nil
}

func (*DummyMap) EnsureExists() error {
	return nil
}

func (*DummyMap) MapFD() bpf.MapFD {
	return 0
}

func (*DummyMap) Path() string {
	return "DummyMap"
}

func (*DummyMap) Iter(_ bpf.IterCallback) error {
	return nil
}

func (*DummyMap) Update(k, v []byte) error {
	return nil
}

func (*DummyMap) Get(k []byte) ([]byte, error) {
	return nil, unix.ENOENT
}

func (*DummyMap) Delete(k []byte) error {
	return nil
}

func (*DummyMap) CopyDeltaFromOldMap() error {
	return nil
}

func GetMapParams(version int) bpf.MapParameters {
        switch version {
        case 2:
                return v2.MockMapParams
        case 3:
                return v3.MockMapParams
        case 4:
                return v4.MockMapParams
        case 5:
                return v5.MockMapParams
        default:
                return v5.MockMapParams
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
                var key v3.Key
                var val v3.Value
                copy(key[:], k)
                copy(val[:], v)
                return key, val
        case 4:
                var key v4.Key
                var val v4.Value
                copy(key[:], k)
                copy(val[:], v)
                return key, val
        case 5:
                var key v5.Key
                var val v5.Value
                copy(key[:], k)
                copy(val[:], v)
                return key, val
        default:
                var key v5.Key
                var val v5.Value
                copy(key[:], k)
                copy(val[:], v)
                return key, val
        }
}

func MapV2(mc *bpf.MapContext) bpf.Map {
        b := mc.NewPinnedMap(v2.MockMapParams)
        b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
        b.(*bpf.PinnedMap).GetMapParams = GetMapParams
        b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
        return b
}

func MapV3(mc *bpf.MapContext) bpf.Map {
        b := mc.NewPinnedMap(v3.MockMapParams)
        b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
        b.(*bpf.PinnedMap).GetMapParams = GetMapParams
        b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
        return b
}

func MapV4(mc *bpf.MapContext) bpf.Map {
        b := mc.NewPinnedMap(v4.MockMapParams)
        b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
        b.(*bpf.PinnedMap).GetMapParams = GetMapParams
        b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
        return b
}

func MapV5(mc *bpf.MapContext) bpf.Map {
        b := mc.NewPinnedMap(v5.MockMapParams)
        b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
        b.(*bpf.PinnedMap).GetMapParams = GetMapParams
        b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
        return b
}
