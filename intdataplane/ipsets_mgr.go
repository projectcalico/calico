// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
)

// ipSetsManager simply passes through IP set updates from the datastore to the ipsets.IPSets
// dataplane layer.
type ipSetsManager struct {
	ipsetReg ipsetsRegistry
	maxSize  int
}

func newIPSetsManager(ipsets ipsetsRegistry, maxIPSetSize int) *ipSetsManager {
	return &ipSetsManager{
		ipsetReg: ipsets,
		maxSize:  maxIPSetSize,
	}
}

func (m *ipSetsManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IPSetDeltaUpdate:
		m.ipsetReg.AddMembers(msg.Id, msg.AddedMembers)
		m.ipsetReg.RemoveMembers(msg.Id, msg.RemovedMembers)
	case *proto.IPSetUpdate:
		metadata := ipsets.IPSetMetadata{
			Type:    ipsets.IPSetTypeHashIP,
			SetID:   msg.Id,
			MaxSize: m.maxSize,
		}
		m.ipsetReg.AddOrReplaceIPSet(metadata, msg.Members)
	case *proto.IPSetRemove:
		m.ipsetReg.RemoveIPSet(msg.Id)
	}
}

func (m *ipSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
