// Copyright (c) 2016-2017, 2019 Tigera, Inc. All rights reserved.
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

type ipSetsManagerCallbacks struct {
	addMembersIPSet    *AddMembersIPSetFuncs
	removeMembersIPSet *RemoveMembersIPSetFuncs
	replaceIPSet       *ReplaceIPSetFuncs
	removeIPSet        *RemoveIPSetFuncs
}

func newIPSetsManagerCallbacks(callbacks *callbacks, ipFamily ipsets.IPFamily) ipSetsManagerCallbacks {
	if ipFamily == ipsets.IPFamilyV4 {
		return ipSetsManagerCallbacks{
			addMembersIPSet:    callbacks.AddMembersIPSetV4,
			removeMembersIPSet: callbacks.RemoveMembersIPSetV4,
			replaceIPSet:       callbacks.ReplaceIPSetV4,
			removeIPSet:        callbacks.RemoveIPSetV4,
		}
	} else {
		return ipSetsManagerCallbacks{
			addMembersIPSet:    &AddMembersIPSetFuncs{},
			removeMembersIPSet: &RemoveMembersIPSetFuncs{},
			replaceIPSet:       &ReplaceIPSetFuncs{},
			removeIPSet:        &RemoveIPSetFuncs{},
		}
	}
}

func (c *ipSetsManagerCallbacks) InvokeAddMembersIPSet(setID string, members set.Set) {
	c.addMembersIPSet.Invoke(setID, members)
}

func (c *ipSetsManagerCallbacks) InvokeRemoveMembersIPSet(setID string, members set.Set) {
	c.removeMembersIPSet.Invoke(setID, members)
}

func (c *ipSetsManagerCallbacks) InvokeReplaceIPSet(setID string, members set.Set) {
	c.replaceIPSet.Invoke(setID, members)
}

func (c *ipSetsManagerCallbacks) InvokeRemoveIPSet(setID string) {
	c.removeIPSet.Invoke(setID)
}

// ipSetsManager simply passes through IP set updates from the datastore to the ipsets.IPSets
// dataplane layer.
type ipSetsManager struct {
	ipsetsDataplane ipsetsDataplane
	maxSize         int
	callbacks       ipSetsManagerCallbacks
}

func newIPSetsManager(ipsets_ ipsetsDataplane, maxIPSetSize int, callbacks *callbacks) *ipSetsManager {
	return &ipSetsManager{
		ipsetsDataplane: ipsets_,
		maxSize:         maxIPSetSize,
		callbacks:       newIPSetsManagerCallbacks(callbacks, ipsets_.GetIPFamily()),
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
		m.callbacks.InvokeAddMembersIPSet(msg.Id, membersToSet(msg.AddedMembers))
		m.ipsetsDataplane.RemoveMembers(msg.Id, msg.RemovedMembers)
		m.callbacks.InvokeRemoveMembersIPSet(msg.Id, membersToSet(msg.RemovedMembers))
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
		m.callbacks.InvokeReplaceIPSet(msg.Id, membersToSet(msg.Members))
	case *proto.IPSetRemove:
		log.WithField("ipSetId", msg.Id).Debug("IP set remove")
		m.ipsetsDataplane.RemoveIPSet(msg.Id)
		m.callbacks.InvokeRemoveIPSet(msg.Id)
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
