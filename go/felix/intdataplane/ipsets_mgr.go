// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/proto"
)

type ipSetsManager struct {
	ipsets *ipsets.IPSets
}

func newIPSetsManager(ipsets *ipsets.IPSets) *ipSetsManager {
	return &ipSetsManager{
		ipsets: ipsets,
	}
}

func (d *ipSetsManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IPSetDeltaUpdate:
		// TODO(smc) Feels ugly to do the fan-out here.
		d.ipsets.AddIPsToIPSet(msg.Id, msg.AddedMembers)
		d.ipsets.RemoveIPsFromIPSet(msg.Id, msg.RemovedMembers)
	case *proto.IPSetUpdate:
		d.ipsets.CreateOrReplaceIPSet(ipsets.IPSetMetadata{
			Type:    ipsets.IPSetTypeHashIP,
			SetID:   msg.Id,
			MaxSize: 1024 * 1024,
		}, msg.Members)
	case *proto.IPSetRemove:
		d.ipsets.RemoveIPSet(msg.Id)
	}
}

func (m *ipSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
