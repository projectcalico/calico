// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"reflect"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/sirupsen/logrus"
)

type ActiveQoSPolicyCalculator struct {
	allPolicies map[string]*v3.QoSPolicy

	// Label index, matching policy selectors against local endpoints.
	labelIndex *labelindex.InheritIndex
}

func NewActiveQoSPolicyCalculator() *ActiveQoSPolicyCalculator {
	aqpc := &ActiveQoSPolicyCalculator{
		allPolicies: map[string]*v3.QoSPolicy{},
	}
	aqpc.labelIndex = labelindex.NewInheritIndex(arc.onMatchStarted, arc.onMatchStopped)
	return aqpc
}

func (aqpc *ActiveQoSPolicyCalculator) RegisterWith(localEndpointDispatcher, allUpdDispatcher *dispatcher.Dispatcher) {
	// It needs all local endpoints.
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, aqpc.OnUpdate)
	// It also needs QoS Policy resource.
	allUpdDispatcher.Register(model.ResourceKey{}, aqpc.OnUpdate)
}

func (aqpc *ActiveQoSPolicyCalculator) OnUpdate(update api.Update) (_ bool) {
	logCxt := logrus.WithField("update", update)
	switch id := update.Key.(type) {
	/*case model.WorkloadEndpointKey:
	// Delegate to the label index.  It will call us back when the match status changes.
	abp.labelIndex.OnUpdate(update)*/
	case model.ResourceKey:
		switch id.Kind {
		case v3.KindQoSPolicy:
			if update.Value != nil {
				logCxt.Info("Updating aqp with QoSPolicy")

				// Save off the peer so that we can re-do the match if the node labels are updated.
				qPolicy := update.Value.(*v3.QoSPolicy)
				name := qPolicy.Name
				aqpc.allPolicies[name] = qPolicy

				if !aqpc.bgpPeerSelectsLocalNode(qPolicy) {
					// Trying to delete QoSPolicy if it does not select the host.
					aqpc.onPeerInactive(name)
				} else {
					aqpc.onPeerActive(qPolicy)
				}
			} else {
				logCxt.Debug("Deleting QoSPolicy from aqp")
				aqpc.onPeerInactive(id.Name)
				delete(aqpc.allPolicies, id.Name)
			}
		default:
			// Ignore other kinds of v3 resource.
		}
	default:
		logrus.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return

}
