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

package mock

import (
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

type Map struct {
	sync.Mutex
	maps.MapParameters
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

func (m *Map) MapFD() maps.FD {
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
	return m.VersionedFilename()
}

func (m *Map) Iter(f maps.IterCallback) error {
	m.IterCount++
	if m.IterErr != nil {
		return m.IterErr
	}

	// Take a copy so that we don't run into trouble with the callback calling
	// methods that take locks.
	contents := m.copyContents()
	for kstr, vstr := range contents {
		action := f([]byte(kstr), []byte(vstr))
		if action == maps.IterDelete {
			delete(m.Contents, kstr)
		}
	}
	return nil
}

func (m *Map) Size() int {
	return m.MapParameters.MaxEntries
}

func (m *Map) copyContents() map[string]string {
	m.Lock()
	defer m.Unlock()
	contentsCopy := map[string]string{}
	for k, v := range m.Contents {
		contentsCopy[k] = v
	}
	return contentsCopy
}

func (m *Map) Update(k, v []byte) error {
	m.Lock()
	defer m.Unlock()

	return m.updateUnlocked(k, v)
}

func (m *Map) updateUnlocked(k, v []byte) error {
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

func (m *Map) UpdateWithFlags(k, v []byte, flags int) error {
	m.Lock()
	defer m.Unlock()

	if (flags & unix.BPF_EXIST) != 0 {
		if _, ok := m.Contents[string(k)]; ok {
			return fmt.Errorf("key exists")
		}
	}

	return m.updateUnlocked(k, v)
}

func (m *Map) Get(k []byte) ([]byte, error) {
	m.Lock()
	defer m.Unlock()

	m.GetCount++

	vstr, ok := m.Contents[string(k)]
	if !ok {
		return nil, unix.ENOENT
	}
	return []byte(vstr), nil
}

func (m *Map) Delete(k []byte) error {
	m.Lock()
	defer m.Unlock()

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

func (m *Map) DeleteIfExists(k []byte) error {
	return m.Delete(k)
}

func (m *Map) OpCount() int {
	return m.UpdateCount + m.IterCount + m.GetCount + m.DeleteCount
}

func (m *Map) CopyDeltaFromOldMap() error {
	return nil
}

func (m *Map) ContainsKey(k []byte) bool {
	m.Lock()
	defer m.Unlock()

	_, ok := m.Contents[string(k)]
	return ok
}

func (m *Map) ContainsKV(k, v []byte) bool {
	val, ok := m.Contents[string(k)]

	if !ok {
		return false
	}

	return val == string(v)
}

func (m *Map) IsEmpty() bool {
	return len(m.Contents) == 0
}

func (*Map) ErrIsNotExists(err error) bool {
	return maps.IsNotExists(err)
}

func NewMockMap(params maps.MapParameters) *Map {
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

var _ maps.Map = (*Map)(nil)

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

func (*DummyMap) MapFD() maps.FD {
	return 0
}

func (*DummyMap) Path() string {
	return "DummyMap"
}

func (*DummyMap) Iter(_ maps.IterCallback) error {
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

func (*DummyMap) Size() int {
	return 0
}

func (*DummyMap) CopyDeltaFromOldMap() error {
	return nil
}

func (*DummyMap) ErrIsNotExists(err error) bool {
	return maps.IsNotExists(err)
}
