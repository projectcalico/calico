// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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

package ipsets

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
	GetDesiredMembers(setID string) (set.Set[string], error)
	QueueResync()
	ApplyUpdates(ipsetFilter func(ipSetName string) bool) (programmedIPs set.Set[string])
	ApplyDeletions() (reschedule bool)
	SetFilter(neededIPSets set.Set[string])
}

// Except for domain IP sets, IPSetsManager simply passes through IP set updates from the datastore
// to the ipsets.IPSets dataplane layer.  For domain IP sets - which hereafter we'll just call
// "domain sets" - IPSetsManager handles the resolution from domain names to expiring IPs.
type IPSetsManager struct {
	dataplanes []IPSetsDataplane
	maxSize    int
	lg         *log.Entry
}

func NewIPSetsManager(name string, ipsets_ IPSetsDataplane, maxIPSetSize int) *IPSetsManager {
	m := &IPSetsManager{
		maxSize: maxIPSetSize,
		lg:      log.WithField("name", name),
	}

	if ipsets_ != nil {
		m.dataplanes = append(m.dataplanes, ipsets_)
	}

	return m
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
		members, err = dp.GetDesiredMembers(setID)
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
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set delta update")
		for _, dp := range m.dataplanes {
			dp.AddMembers(msg.Id, msg.AddedMembers)
			dp.RemoveMembers(msg.Id, msg.RemovedMembers)
		}
	case *proto.IPSetUpdate:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set update")
		var setType ipsets.IPSetType
		switch msg.Type {
		case proto.IPSetUpdate_IP:
			setType = ipsets.IPSetTypeHashIP
		case proto.IPSetUpdate_NET:
			setType = ipsets.IPSetTypeHashNet
		case proto.IPSetUpdate_IP_AND_PORT:
			setType = ipsets.IPSetTypeHashIPPort
		default:
			m.lg.WithField("type", msg.Type).Panic("Unknown IP set type")
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
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set remove")
		for _, dp := range m.dataplanes {
			dp.RemoveIPSet(msg.Id)
		}
	}
}

func (m *IPSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
