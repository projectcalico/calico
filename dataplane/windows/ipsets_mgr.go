//+build windows

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package windataplane

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dataplane/windows/ipsets"
	"github.com/projectcalico/felix/proto"
)

// ipSetsManager simply passes through IP set updates from the datastore to the ipsets.IPSets
// dataplane layer.
type ipSetsManager struct {
	ipsetsDataplane ipsets.IPSetsDataplane
}

func newIPSetsManager(ipsets ipsets.IPSetsDataplane) *ipSetsManager {
	return &ipSetsManager{
		ipsetsDataplane: ipsets,
	}
}

// OnUpdate is called by the main dataplane driver loop during the first phase. It processes
// specific types of updates from the datastore.
func (m *ipSetsManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.IPSetDeltaUpdate:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetDeltaUpdate")
		m.ipsetsDataplane.AddMembers(msg.Id, msg.AddedMembers)
		m.ipsetsDataplane.RemoveMembers(msg.Id, msg.RemovedMembers)
	case *proto.IPSetUpdate:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetUpdate")
		metadata := ipsets.IPSetMetadata{
			Type:  ipsets.IPSetTypeHashIP,
			SetID: msg.Id,
		}
		m.ipsetsDataplane.AddOrReplaceIPSet(metadata, msg.Members)
	case *proto.IPSetRemove:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetRemove")
		m.ipsetsDataplane.RemoveIPSet(msg.Id)
	}
}

func (m *ipSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
