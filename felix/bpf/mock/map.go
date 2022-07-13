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

package mock

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
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

func (m *Map) Close() error {
	m.logCxt.Info("Close called")
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

func (m *Map) ContainsKey(k []byte) bool {
	_, ok := m.Contents[string(k)]
	return ok
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

func (*DummyMap) Close() error {
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
