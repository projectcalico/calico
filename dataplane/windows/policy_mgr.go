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

	"github.com/projectcalico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/felix/proto"
)

// policyManager simply passes through Policy and Profile updates from the datastore to the
// PolicySets dataplane layer.
type policyManager struct {
	policysetsDataplane policysets.PolicySetsDataplane
}

func newPolicyManager(policysets policysets.PolicySetsDataplane) *policyManager {
	return &policyManager{
		policysetsDataplane: policysets,
	}
}

// OnUpdate is called by the main dataplane driver loop during the first phase. It processes
// specific types of updates from the datastore.
func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.ActivePolicyUpdate:
		log.WithField("policyID", msg.Id).Info("Processing ActivePolicyUpdate")
		m.policysetsDataplane.AddOrReplacePolicySet(policysets.PolicyNamePrefix+msg.Id.Name, msg.Policy)
	case *proto.ActivePolicyRemove:
		log.WithField("policyID", msg.Id).Info("Processing ActivePolicyRemove")
		m.policysetsDataplane.RemovePolicySet(policysets.PolicyNamePrefix + msg.Id.Name)
	case *proto.ActiveProfileUpdate:
		log.WithField("profileId", msg.Id).Info("Processing ActiveProfileUpdate")
		m.policysetsDataplane.AddOrReplacePolicySet(policysets.ProfileNamePrefix+msg.Id.Name, msg.Profile)
	case *proto.ActiveProfileRemove:
		log.WithField("profileId", msg.Id).Info("Processing ActiveProfileRemove")
		m.policysetsDataplane.RemovePolicySet(policysets.ProfileNamePrefix + msg.Id.Name)
	}
}

func (m *policyManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
