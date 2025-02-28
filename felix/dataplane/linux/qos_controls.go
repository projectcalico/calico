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

	"github.com/projectcalico/calico/felix/dataplane/linux/bwp"
	"github.com/projectcalico/calico/felix/dataplane/linux/qos"
	"github.com/projectcalico/calico/felix/proto"
)

func (m *endpointManager) maybeUpdateQoSBandwidth(old, new *proto.WorkloadEndpoint) error {
	var err error
	var errs []error

	var oldName, newName string

	var currentIngress, desiredIngress qos.QoSState
	var currentEgress, desiredEgress qos.QoSState

	if old != nil {
		oldName = old.Name
	}

	if new != nil {
		newName = new.Name
		if new.QosControls != nil {
			if new.QosControls.IngressBandwidth != 0 {
				rate, buffer, limit := bwp.GetTBFValues(uint64(new.QosControls.IngressBandwidth), uint64(new.QosControls.IngressBurst))
				desiredIngress = qos.QoSState{
					Rate:   rate,
					Buffer: buffer,
					Limit:  limit,
				}
			}
			if new.QosControls.EgressBandwidth != 0 {
				rate, buffer, limit := bwp.GetTBFValues(uint64(new.QosControls.EgressBandwidth), uint64(new.QosControls.EgressBurst))
				desiredEgress = qos.QoSState{
					Rate:   rate,
					Buffer: buffer,
					Limit:  limit,
				}
			}
		}
		currentIngress, err = qos.ReadIngressQdisc(newName)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading ingress qdisc from workload %s: %v", newName, err))
		}
		currentEgress, err = qos.ReadEgressQdisc(newName)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading egress qdisc from workload %s: %v", newName, err))
		}
	}

	if oldName != newName {
		// Interface name changed, remove QoS state from old if present
		if old != nil {
			// Remove QoS state from old if present
			oldIngress, err := qos.ReadIngressQdisc(oldName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error reading ingress qdisc from workload %s: %v", oldName, err))
			}
			if !oldIngress.Equals(qos.QoSState{}) {
				err := qos.RemoveIngressQdisc(oldName)
				if err != nil {
					errs = append(errs, fmt.Errorf("error removing ingress qdisc from workload %s: %v", oldName, err))
				}
			}
			oldEgress, err := qos.ReadEgressQdisc(oldName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error reading egress qdisc from workload %s: %v", oldName, err))
			}
			if !oldEgress.Equals(qos.QoSState{}) {
				err := qos.RemoveEgressQdisc(oldName)
				if err != nil {
					errs = append(errs, fmt.Errorf("error removing egress qdisc from workload %s: %v", oldName, err))
				}
			}
		}
	}

	if !currentIngress.Equals(desiredIngress) {
		if currentIngress.Equals(qos.QoSState{}) {
			// Current is empty, add only
			err := qos.AddIngressQdisc(new.QosControls.IngressBandwidth, new.QosControls.IngressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding ingress qdisc to workload %s: %v", newName, err))
			}
		} else if desiredIngress.Equals(qos.QoSState{}) {
			// Desired is empty, remove only
			err := qos.RemoveIngressQdisc(newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing ingress qdisc from workload %s: %v", newName, err))
			}
		} else {
			// Both non-empty, change in-place
			err := qos.ChangeIngressQdisc(new.QosControls.IngressBandwidth, new.QosControls.IngressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error changing ingress qdisc on workload %s: %v", newName, err))
			}
		}
	}

	if !currentEgress.Equals(desiredEgress) {
		if currentEgress.Equals(qos.QoSState{}) {
			// Current is empty, add only
			err := qos.AddEgressQdisc(new.QosControls.EgressBandwidth, new.QosControls.EgressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding egress qdisc to workload %s: %v", newName, err))
			}
		} else if desiredEgress.Equals(qos.QoSState{}) {
			// Desired is empty, remove only
			err := qos.RemoveEgressQdisc(newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing egress qdisc from workload %s: %v", newName, err))
			}
		} else {
			// Both non-empty, change in-place
			err := qos.ChangeEgressQdisc(new.QosControls.EgressBandwidth, new.QosControls.EgressBurst, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error changing egress qdisc on workload %s: %v", newName, err))
			}
		}
	}

	return errors.Join(errs...)
}
