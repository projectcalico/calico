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

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// ipSetsManager simply passes through IP set updates from the datastore to the ipsets.IPSets
// dataplane layer.
type ipSetsManager struct {
	dataplanes []ipsetsDataplane
	maxSize    int
}

func newIPSetsManager(ipsets_ ipsetsDataplane, maxIPSetSize int) *ipSetsManager {
	return &ipSetsManager{
		dataplanes: []ipsetsDataplane{ipsets_},
		maxSize:    maxIPSetSize,
	}
}

func (m *ipSetsManager) AddDataplane(dp ipsetsDataplane) {
	m.dataplanes = append(m.dataplanes, dp)
}

func (m *ipSetsManager) GetIPSetType(setID string) (typ ipsets.IPSetType, err error) {
	for _, dp := range m.dataplanes {
		typ, err = dp.GetTypeOf(setID)
		if err == nil {
			break
		}
	}
	return
}

func (m *ipSetsManager) GetIPSetMembers(setID string) (members set.Set /*<string>*/, err error) {
	for _, dp := range m.dataplanes {
		members, err = dp.GetMembers(setID)
		if err == nil {
			break
		}
	}
	return
}

func (m *ipSetsManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IPSetDeltaUpdate:
		log.WithField("ipSetId", msg.Id).Debug("IP set delta update")
		for _, dp := range m.dataplanes {
			dp.AddMembers(msg.Id, msg.AddedMembers)
			dp.RemoveMembers(msg.Id, msg.RemovedMembers)
		}
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
		for _, dp := range m.dataplanes {
			dp.AddOrReplaceIPSet(metadata, msg.Members)
		}
	case *proto.IPSetRemove:
		log.WithField("ipSetId", msg.Id).Debug("IP set remove")
		for _, dp := range m.dataplanes {
			dp.RemoveIPSet(msg.Id)
		}
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
