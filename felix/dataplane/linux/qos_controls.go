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
	"github.com/projectcalico/calico/felix/proto"

	"github.com/vishvananda/netlink"
)

func (m *endpointManager) maybeUpdateQoSBandwidth(old, new *proto.WorkloadEndpoint) error {
	var errs []error
	var oldIngressBw, oldEgressBw, newIngressBw, newEgressBw int64
	var oldIngressBurst, oldEgressBurst, newIngressBurst, newEgressBurst int64
	if old != nil && old.QosControls != nil {
		oldIngressBw = old.QosControls.IngressBandwidth
		oldEgressBw = old.QosControls.EgressBandwidth
		oldIngressBurst = old.QosControls.IngressBurst
		oldEgressBurst = old.QosControls.EgressBurst
	}

	if new != nil && new.QosControls != nil {
		newIngressBw = new.QosControls.IngressBandwidth
		newEgressBw = new.QosControls.EgressBandwidth
		newIngressBurst = new.QosControls.IngressBurst
		newEgressBurst = new.QosControls.EgressBurst
	}

	if oldIngressBw != newIngressBw || oldIngressBurst != newIngressBurst {
		if oldIngressBw != 0 {
			err := removeIngressQdisc(old.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing ingress qdisc: %v", err))
			}
		}
		if newIngressBw != 0 {
			err := addIngressQdisc(newIngressBw, newIngressBurst, new.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding ingress qdisc: %v", err))
			}
		}
	}

	if oldEgressBw != newEgressBw || oldEgressBurst != newEgressBurst {
		if oldEgressBw != 0 {
			err := removeEgressQdisc(old.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing egress qdisc: %v", err))
			}
		}
		if newEgressBw != 0 {
			err := addEgressQdisc(newEgressBw, newEgressBurst, new.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding egress qdisc: %v", err))
			}
		}
	}

	return errors.Join(errs...)
}

func addIngressQdisc(bw, burst int64, intf string) error {
	return bwp.CreateIngressQdisc(uint64(bw), uint64(burst), intf)
}

func addEgressQdisc(bw, burst int64, intf string) error {
	mtu, err := bwp.GetMTU(intf)
	if err != nil {
		return fmt.Errorf("Failed to get MTU for interface %s: %v", intf, err)
	}

	ifbDeviceName := bwp.GetIfbDeviceName(intf)

	err = bwp.CreateIfb(ifbDeviceName, mtu)
	if err != nil {
		return fmt.Errorf("Failed to create ifb device %s: %v", ifbDeviceName, err)
	}

	return bwp.CreateEgressQdisc(uint64(bw), uint64(burst), intf, ifbDeviceName)
}

func removeIngressQdisc(intf string) error {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("Failed to get link: %v", err)
	}

	qdiscs, err := bwp.SafeQdiscList(link)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs: %v", err)
	}
	if len(qdiscs) == 0 {
		return fmt.Errorf("Failed to find qdisc")
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if !isTbf {
			break
		}
		err := netlink.QdiscDel(tbf)
		if err != nil {
			return fmt.Errorf("Failed to delete qdisc: %v", err)
		}
	}

	return nil
}

func removeEgressQdisc(intf string) error {
	ifbDeviceName := bwp.GetIfbDeviceName(intf)

	if err := bwp.TeardownIfb(ifbDeviceName); err != nil {
		return fmt.Errorf("Failed to tear down ifb device %s: %v", ifbDeviceName, err)
	}

	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("Failed to get link: %v", err)
	}

	qdiscs, err := bwp.SafeQdiscList(link)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs: %v", err)
	}

	for _, qdisc := range qdiscs {
		ingress, isIngress := qdisc.(*netlink.Ingress)
		if !isIngress {
			break
		}
		err := netlink.QdiscDel(ingress)
		if err != nil {
			return fmt.Errorf("Failed to delete qdisc: %v", err)
		}
	}

	return nil
}
