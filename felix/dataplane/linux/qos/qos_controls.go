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

package qos

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/bwp"
)

type QoSState struct {
	Rate   uint64
	Buffer uint32
	Limit  uint32
}

func (s QoSState) Equals(other QoSState) bool {
	return s.Rate == other.Rate && s.Buffer == other.Buffer && s.Limit == other.Limit
}

func AddIngressQdisc(bw, burst int64, intf string) error {
	return bwp.CreateIngressQdisc(uint64(bw), uint64(burst), intf)
}

func AddEgressQdisc(bw, burst int64, intf string) error {
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

func RemoveIngressQdisc(intf string) error {
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

func RemoveEgressQdisc(intf string) error {
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

func ChangeIngressQdisc(bw, burst int64, intf string) error {
	return bwp.UpdateIngressQdisc(uint64(bw), uint64(burst), intf)
}

func ChangeEgressQdisc(bw, burst int64, intf string) error {
	ifbDeviceName := bwp.GetIfbDeviceName(intf)

	return bwp.UpdateEgressQdisc(uint64(bw), uint64(burst), ifbDeviceName)
}

func ReadIngressQdisc(intf string) (QoSState, error) {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return QoSState{}, fmt.Errorf("Failed to get link %s: %v", intf, err)
	}

	qdiscs, err := bwp.SafeQdiscList(link)
	if err != nil {
		return QoSState{}, fmt.Errorf("Failed to list qdiscs on link %s: %v", intf, err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if isTbf {
			return QoSState{Rate: tbf.Rate, Buffer: tbf.Buffer}, nil
		}
	}

	return QoSState{}, nil
}

func ReadEgressQdisc(intf string) (QoSState, error) {
	ifbDeviceName := bwp.GetIfbDeviceName(intf)

	link, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return QoSState{}, fmt.Errorf("Failed to get link %s: %v", ifbDeviceName, err)
	}

	qdiscs, err := bwp.SafeQdiscList(link)
	if err != nil {
		return QoSState{}, fmt.Errorf("Failed to list qdiscs on link %s: %v", ifbDeviceName, err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if isTbf {
			return QoSState{Rate: tbf.Rate, Buffer: tbf.Buffer}, nil
		}
	}

	return QoSState{}, nil
}
