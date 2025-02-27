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

package intdataplane

import (
	"errors"
	"fmt"

	"github.com/projectcalico/calico/felix/dataplane/linux/qos"
	"github.com/projectcalico/calico/felix/proto"
)

func (m *endpointManager) maybeUpdateQoSBandwidth(old, new *proto.WorkloadEndpoint) error {
	var errs []error

	var oldName, newName string
	var oldIngressBw, oldEgressBw, newIngressBw, newEgressBw int64
	var oldIngressBurst, oldEgressBurst, newIngressBurst, newEgressBurst int64

	if old != nil {
		oldName = old.Name
		if old.QosControls != nil {
			oldIngressBw = old.QosControls.IngressBandwidth
			oldEgressBw = old.QosControls.EgressBandwidth
			oldIngressBurst = old.QosControls.IngressBurst
			oldEgressBurst = old.QosControls.EgressBurst
		}
	}

	if new != nil {
		newName = new.Name
		if new.QosControls != nil {
			newIngressBw = new.QosControls.IngressBandwidth
			newEgressBw = new.QosControls.EgressBandwidth
			newIngressBurst = new.QosControls.IngressBurst
			newEgressBurst = new.QosControls.EgressBurst
		}
	}

	if oldName != newName || oldIngressBw != newIngressBw || oldIngressBurst != newIngressBurst {
		if oldName == newName && oldIngressBw != 0 && newIngressBw != 0 {
			err := qos.ChangeIngressQdisc(newIngressBw, newIngressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error changing ingress qdisc on workload %s: %v", newName, err))
			}
		} else if oldName != "" && oldIngressBw != 0 {
			err := qos.RemoveIngressQdisc(oldName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing ingress qdisc from workload %s: %v", oldName, err))
			}
		} else if newName != "" && newIngressBw != 0 {
			err := qos.AddIngressQdisc(newIngressBw, newIngressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding ingress qdisc to workload %s: %v", newName, err))
			}
		}
	}

	if oldEgressBw != newEgressBw || oldEgressBurst != newEgressBurst {
		if oldName == newName && oldEgressBw != 0 && newEgressBw != 0 {
			err := qos.ChangeEgressQdisc(newEgressBw, newEgressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error changing egress qdisc on workload %s: %v", newName, err))
			}
		} else if oldName != "" && oldEgressBw != 0 {
			err := qos.RemoveEgressQdisc(oldName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing egress qdisc from workload %s: %v", oldName, err))
			}
		} else if newName != "" && newEgressBw != 0 {
			err := qos.AddEgressQdisc(newEgressBw, newEgressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding egress qdisc to workload %s: %v", newName, err))
			}
		}
	}

	return errors.Join(errs...)
}
