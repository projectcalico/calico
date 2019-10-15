// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

type conntrackManager struct {
	ctMap bpf.Map
}

const conntrackKeySize = 16
const conntrackValueSize = 48

type ConntrackEntry [conntrackValueSize]byte

func newBPFConntrackManager() *conntrackManager {
	return &conntrackManager{
		ctMap: ConntrackMap(),
	}
}

func ConntrackMap() bpf.Map {
	return bpf.NewPinnedMap(
		"calico_ct_map_v4",
		"/sys/fs/bpf/tc/globals/calico_ct_map_v4",
		"hash",
		conntrackKeySize,
		conntrackValueSize,
		512000,
		unix.BPF_F_NO_PREALLOC)
}

func (m *conntrackManager) OnUpdate(msg interface{}) {
}

func (m *conntrackManager) CompleteDeferredWork() error {
	err := m.ctMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create Conntrack map")
	}
	return nil
}
