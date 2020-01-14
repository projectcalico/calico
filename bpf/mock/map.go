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

package mock

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
)

type Map struct {
	bpf.MapParameters
	logCxt *logrus.Entry

	Contents map[string]string
}

func (m Map) MapFD() bpf.MapFD {
	panic("implement me")
}

func (m Map) EnsureExists() error {
	m.logCxt.Info("EnsureExists called")
	return nil
}

func (m *Map) GetName() string {
	return m.Name
}

func (m *Map) Path() string {
	return m.Filename
}

func (m Map) Iter(f bpf.MapIter) error {
	for kstr, vstr := range m.Contents {
		f([]byte(kstr), []byte(vstr))
	}
	return nil
}

func (m Map) Update(k, v []byte) error {
	if len(k) != m.KeySize {
		m.logCxt.Panicf("Key had wrong size (%d)", len(k))
	}
	if len(v) != m.ValueSize {
		m.logCxt.Panicf("Value had wrong size (%d)", len(v))
	}
	m.Contents[string(k)] = string(v)
	return nil
}

func (m Map) Get(k []byte) ([]byte, error) {
	vstr, ok := m.Contents[string(k)]
	if !ok {
		return nil, unix.ENOENT
	}
	return []byte(vstr), nil
}

func (m Map) Delete(k []byte) error {
	if len(k) != m.KeySize {
		m.logCxt.Panicf("Key had wrong size (%d)", len(k))
	}
	delete(m.Contents, string(k))
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
