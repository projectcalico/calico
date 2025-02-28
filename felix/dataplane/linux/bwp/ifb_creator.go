// Copyright 2018 CNI authors
// Changes copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package bwp

import (
	"fmt"
	"net"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ip"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const latencyInMillis = 25

func CreateIfb(ifbDeviceName string, mtu int) error {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = ifbDeviceName
	linkAttrs.Flags = net.FlagUp
	linkAttrs.MTU = mtu

	err := netlink.LinkAdd(&netlink.Ifb{
		LinkAttrs: linkAttrs,
	})

	if err != nil {
		return fmt.Errorf("adding link %s: %v", ifbDeviceName, err)
	}

	return nil
}

func TeardownIfb(deviceName string) error {
	_, err := ip.DelLinkByNameAddr(deviceName)
	if err != nil {
		if err == ip.ErrLinkNotFound {
			return nil
		}
		return fmt.Errorf("tearing down link %s: %v", deviceName, err)
	}

	return nil
}

func CreateIngressQdisc(rateInBits, burstInBits uint64, hostDeviceName string) error {
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}
	return createTBF(rateInBits, burstInBits, hostDevice.Attrs().Index)
}

func UpdateIngressQdisc(rateInBits, burstInBits uint64, hostDeviceName string) error {
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}
	return updateTBF(rateInBits, burstInBits, hostDevice.Attrs().Index)
}

func CreateEgressQdisc(rateInBits, burstInBits uint64, hostDeviceName string, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device %s: %v", ifbDeviceName, err)
	}
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device %s: %v", hostDeviceName, err)
	}

	// check if host device has a ingress qdisc
	hasQdisc := false
	qdiscList, err := SafeQdiscList(hostDevice)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs on dev %s: %v", hostDeviceName, err)
	}

	for _, qdisc := range qdiscList {
		_, isIngress := qdisc.(*netlink.Ingress)
		if isIngress {
			hasQdisc = true
		}
	}

	// only add ingress qdisc on host device if it doesn't already exist
	if !hasQdisc {
		qdisc := &netlink.Ingress{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: hostDevice.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0), // ffff:
				Parent:    netlink.HANDLE_INGRESS,
			},
		}

		err = netlink.QdiscAdd(qdisc)
		if err != nil {
			return fmt.Errorf("create ingress qdisc %+v on dev %s: %s", qdisc, hostDeviceName, err)
		}
	}

	// add filter on host device to mirror traffic to ifb device
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Parent:    netlink.MakeHandle(0xffff, 0), // ffff:, same as qdisc.Attrs().Handle
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId:    netlink.MakeHandle(1, 1),
		RedirIndex: ifbDevice.Attrs().Index,
		Actions: []netlink.Action{
			netlink.NewMirredAction(ifbDevice.Attrs().Index),
		},
	}
	err = netlink.FilterAdd(filter)
	if err != nil {
		return fmt.Errorf("add egress filter %+v: %s", filter, err)
	}

	// throttle traffic on ifb device
	err = createTBF(rateInBits, burstInBits, ifbDevice.Attrs().Index)
	if err != nil {
		return fmt.Errorf("create ifb qdisc on dev %s: %v", ifbDeviceName, err)
	}
	return nil
}

func UpdateEgressQdisc(rateInBits, burstInBits uint64, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device %s: %v", ifbDeviceName, err)
	}
	return updateTBF(rateInBits, burstInBits, ifbDevice.Attrs().Index)
}

func GetTBFValues(rateInBits, burstInBits uint64) (rateInBytes uint64, bufferInBytes, limitInBytes uint32) {
	rateInBytes = rateInBits / 8
	burstInBytes := burstInBits / 8
	bufferInBytes = buffer(uint64(rateInBytes), uint32(burstInBytes))
	latency := latencyInUsec(latencyInMillis)
	limitInBytes = limit(uint64(rateInBytes), latency, uint32(burstInBytes))

	return rateInBytes, bufferInBytes, limitInBytes
}

func makeTBF(rateInBits, burstInBits uint64, linkIndex int) (*netlink.Tbf, error) {
	// Equivalent to
	// tc qdisc add dev link root tbf
	//		rate netConf.BandwidthLimits.Rate
	//		burst netConf.BandwidthLimits.Burst
	if rateInBits == 0 {
		return nil, fmt.Errorf("invalid rate: %d", rateInBits)
	}
	if burstInBits == 0 {
		return nil, fmt.Errorf("invalid burst: %d", burstInBits)
	}

	rateInBytes, bufferInBytes, limitInBytes := GetTBFValues(rateInBits, burstInBits)

	qdisc := &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Limit:  uint32(limitInBytes),
		Rate:   uint64(rateInBytes),
		Buffer: uint32(bufferInBytes),
	}

	if qdisc.Limit <= 0 || qdisc.Rate <= 0 || qdisc.Buffer <= 0 {
		return nil, fmt.Errorf("invalid value(s) for qdisc %+v, limit: %v, rate %v, buffer %v, verify bandwidth and burst configuration", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer)
	}

	log.Debugf("create TBF qdisc %+v, limit: %v, rate %v, buffer %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer)

	return qdisc, nil
}

func createTBF(rateInBits, burstInBits uint64, linkIndex int) error {
	// Equivalent to
	// tc qdisc add dev link root tbf

	qdisc, err := makeTBF(rateInBits, burstInBits, linkIndex)
	if err != nil {
		return fmt.Errorf("get TBF qdisc %+v, limit: %v, rate %v, buffer %v: %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}

	err = netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("create TBF qdisc %+v, limit: %v, rate %v, buffer %v: %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}
	return nil
}

func updateTBF(rateInBits, burstInBits uint64, linkIndex int) error {
	// Equivalent to
	// tc qdisc change dev link root tbf

	qdisc, err := makeTBF(rateInBits, burstInBits, linkIndex)
	if err != nil {
		return fmt.Errorf("get TBF qdisc %+v, limit: %v, rate %v, buffer %v: %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}

	err = netlink.QdiscChange(qdisc)
	if err != nil {
		return fmt.Errorf("update TBF qdisc %+v, limit: %v, rate %v, buffer %v: %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}
	return nil
}

func time2Tick(time uint32) uint32 {
	return uint32(float64(time) * float64(netlink.TickInUsec()))
}

func buffer(rate uint64, burst uint32) uint32 {
	return time2Tick(uint32(float64(burst) * float64(netlink.TIME_UNITS_PER_SEC) / float64(rate)))
}

func limit(rate uint64, latency float64, buffer uint32) uint32 {
	return uint32(float64(rate)*latency/float64(netlink.TIME_UNITS_PER_SEC)) + buffer
}

func latencyInUsec(latencyInMillis float64) float64 {
	return float64(netlink.TIME_UNITS_PER_SEC) * (latencyInMillis / 1000.0)
}
