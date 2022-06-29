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

package common

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type IPSetsDataplane interface {
	AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveIPSet(setID string)
	GetIPFamily() ipsets.IPFamily
	GetTypeOf(setID string) (ipsets.IPSetType, error)
	GetMembers(setID string) (set.Set[string], error)
	QueueResync()
	ApplyUpdates()
	ApplyDeletions()
}

// Except for domain IP sets, IPSetsManager simply passes through IP set updates from the datastore
// to the ipsets.IPSets dataplane layer.  For domain IP sets - which hereafter we'll just call
// "domain sets" - IPSetsManager handles the resolution from domain names to expiring IPs.
type IPSetsManager struct {
	dataplanes []IPSetsDataplane
	maxSize    int
}

func NewIPSetsManager(ipsets_ IPSetsDataplane, maxIPSetSize int) *IPSetsManager {
	return &IPSetsManager{
		dataplanes: []IPSetsDataplane{ipsets_},
		maxSize:    maxIPSetSize,
	}
}

func (m *IPSetsManager) AddDataplane(dp IPSetsDataplane) {
	m.dataplanes = append(m.dataplanes, dp)
}

func (m *IPSetsManager) GetIPSetType(setID string) (typ ipsets.IPSetType, err error) {
	for _, dp := range m.dataplanes {
		typ, err = dp.GetTypeOf(setID)
		if err == nil {
			break
		}
	}
	return
}

func (m *IPSetsManager) GetIPSetMembers(setID string) (members set.Set[string], err error) {
	for _, dp := range m.dataplanes {
		members, err = dp.GetMembers(setID)
		if err == nil {
			break
		}
	}
	return
}

func (m *IPSetsManager) OnUpdate(msg interface{}) {
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

func (m *IPSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
