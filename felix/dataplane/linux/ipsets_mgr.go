// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// ipSetsManager simply passes through IP set updates from the datastore to the ipsets.IPSets
// dataplane layer.
type ipSetsManager struct {
	ipsetsDataplane ipsetsDataplane
	maxSize         int
}

func newIPSetsManager(ipsets_ ipsetsDataplane, maxIPSetSize int) *ipSetsManager {
	return &ipSetsManager{
		ipsetsDataplane: ipsets_,
		maxSize:         maxIPSetSize,
	}
}

func (m *ipSetsManager) GetIPSetType(setID string) (ipsets.IPSetType, error) {
	return m.ipsetsDataplane.GetTypeOf(setID)
}

func (m *ipSetsManager) GetIPSetMembers(setID string) (set.Set /*<string>*/, error) {
	return m.ipsetsDataplane.GetMembers(setID)
}

func (m *ipSetsManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IPSetDeltaUpdate:
		log.WithField("ipSetId", msg.Id).Debug("IP set delta update")
		m.ipsetsDataplane.AddMembers(msg.Id, msg.AddedMembers)
		m.ipsetsDataplane.RemoveMembers(msg.Id, msg.RemovedMembers)
	case *proto.IPSetUpdate:
		log.WithField("ipSetId", msg.Id).Debug("IP set update")
		var setType ipsets.IPSetType
		switch msg.Type {
		case proto.IPSetUpdate_IP:
			setType = ipsets.IPSetTypeHashIP
		case proto.IPSetUpdate_NET:
			setType = ipsets.IPSetTypeHashNet
		case proto.IPSetUpdate_IP_AND_PORT:
			setType = ipsets.IPSetTypeHashIPPort
		default:
			log.WithField("type", msg.Type).Panic("Unknown IP set type")
		}
		metadata := ipsets.IPSetMetadata{
			Type:    setType,
			SetID:   msg.Id,
			MaxSize: m.maxSize,
		}
		m.ipsetsDataplane.AddOrReplaceIPSet(metadata, msg.Members)
	case *proto.IPSetRemove:
		log.WithField("ipSetId", msg.Id).Debug("IP set remove")
		m.ipsetsDataplane.RemoveIPSet(msg.Id)
	}
}

func (m *ipSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}

func membersToSet(members []string) set.Set /*string*/ {
	membersSet := set.New()
	for _, m := range members {
		membersSet.Add(m)
	}

	return membersSet
}
