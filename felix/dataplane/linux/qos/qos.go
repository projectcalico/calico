// Copyright (c) 2025 Tigera, Inc. All rights reserved.
// This code derived from the CNI bandwidth plugin, copyright 2018 CNI authors.
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
	"net"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type TokenBucketState struct {
	Rate   uint64
	Buffer uint32
	Limit  uint32
}

func (s *TokenBucketState) Equals(other *TokenBucketState) bool {
	if s == nil && other == nil {
		return true
	}
	if (s == nil && other != nil) || (s != nil && other == nil) {
		return false
	}
	return s.Rate == other.Rate && s.Buffer == other.Buffer && s.Limit == other.Limit
}

func AddEgressQdisc(tbs *TokenBucketState, intf string) error {
	mtu, err := GetMTU(intf)
	if err != nil {
		return fmt.Errorf("Failed to get MTU for interface %s: %v", intf, err)
	}

	ifbDeviceName := GetIfbDeviceName(intf)

	err = CreateIfb(ifbDeviceName, mtu)
	if err != nil {
		return fmt.Errorf("Failed to create ifb device %s: %v", ifbDeviceName, err)
	}

	return CreateEgressQdisc(tbs, intf, ifbDeviceName)
}

func RemoveIngressQdisc(intf string) error {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("Failed to get link: %w", err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs: %w", err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if !isTbf {
			break
		}
		err := netlink.QdiscDel(tbf)
		if err != nil {
			return fmt.Errorf("Failed to delete qdisc: %w", err)
		}
	}

	return nil
}

func RemoveEgressQdisc(intf string) error {
	ifbDeviceName := GetIfbDeviceName(intf)

	if err := TeardownIfb(ifbDeviceName); err != nil {
		return fmt.Errorf("Failed to tear down ifb device %s: %w", ifbDeviceName, err)
	}

	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("Failed to get link: %w", err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs: %w", err)
	}

	for _, qdisc := range qdiscs {
		ingress, isIngress := qdisc.(*netlink.Ingress)
		if !isIngress {
			break
		}
		err := netlink.QdiscDel(ingress)
		if err != nil {
			return fmt.Errorf("Failed to delete qdisc: %w", err)
		}
	}

	return nil
}

func ReadIngressQdisc(intf string) (*TokenBucketState, error) {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return nil, fmt.Errorf("Failed to get link %s: %w", intf, err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("Failed to list qdiscs on link %s: %w", intf, err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if isTbf {
			return &TokenBucketState{Rate: tbf.Rate, Buffer: tbf.Buffer}, nil
		}
	}

	return nil, nil
}

func ReadEgressQdisc(intf string) (*TokenBucketState, error) {
	ifbDeviceName := GetIfbDeviceName(intf)

	link, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return nil, fmt.Errorf("Failed to get link %s: %w", ifbDeviceName, err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("Failed to list qdiscs on link %s: %w", ifbDeviceName, err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if isTbf {
			return &TokenBucketState{Rate: tbf.Rate, Buffer: tbf.Buffer}, nil
		}
	}

	return nil, nil
}

const maxIfbDeviceLength = 15
const ifbDevicePrefix = "bwcali"

func SafeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := []netlink.Qdisc{}
	for _, qdisc := range qdiscs {
		// filter out pfifo_fast qdiscs because
		// older kernels don't return them
		_, pfifo := qdisc.(*netlink.PfifoFast)
		if !pfifo {
			result = append(result, qdisc)
		}
	}
	return result, nil
}

func GetMTU(deviceName string) (int, error) {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return -1, err
	}

	return link.Attrs().MTU, nil
}

func GetIfbDeviceName(deviceName string) string {
	return utils.MustFormatHashWithPrefix(maxIfbDeviceLength, ifbDevicePrefix, deviceName)
}

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
		return fmt.Errorf("adding link %s: %w", ifbDeviceName, err)
	}

	return nil
}

func TeardownIfb(deviceName string) error {
	_, err := ip.DelLinkByNameAddr(deviceName)
	if err != nil {
		if err == ip.ErrLinkNotFound {
			return nil
		}
		return fmt.Errorf("tearing down link %s: %w", deviceName, err)
	}

	return nil
}

func CreateIngressQdisc(tbs *TokenBucketState, hostDeviceName string) error {
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}
	return createTBF(tbs, hostDevice.Attrs().Index)
}

func UpdateIngressQdisc(tbs *TokenBucketState, hostDeviceName string) error {
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}
	return updateTBF(tbs, hostDevice.Attrs().Index)
}

func CreateEgressQdisc(tbs *TokenBucketState, hostDeviceName string, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device %s: %w", ifbDeviceName, err)
	}
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device %s: %w", hostDeviceName, err)
	}

	// check if host device has a ingress qdisc
	hasQdisc := false
	qdiscList, err := SafeQdiscList(hostDevice)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs on dev %s: %w", hostDeviceName, err)
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
	err = createTBF(tbs, ifbDevice.Attrs().Index)
	if err != nil {
		return fmt.Errorf("create ifb qdisc on dev %s: %w", ifbDeviceName, err)
	}
	return nil
}

func UpdateEgressQdisc(tbs *TokenBucketState, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device %s: %w", ifbDeviceName, err)
	}
	return updateTBF(tbs, ifbDevice.Attrs().Index)
}

func GetTBFValues(rateBitsPerSec, burstBits uint64) *TokenBucketState {
	rateBytesPerSec := rateBitsPerSec / 8
	burstBytes := burstBits / 8

	time2Tick := uint32(float64(burstBytes) * float64(1000000) / float64(rateBytesPerSec))
	bufferBytes := uint32(float64(time2Tick) * float64(netlink.TickInUsec()))

	latency := float64(latencyInMillis * 1000)
	limitBytes := uint32(float64(rateBytesPerSec)*latency/float64(1000000)) + bufferBytes

	return &TokenBucketState{
		Rate:   rateBytesPerSec,
		Buffer: bufferBytes,
		Limit:  limitBytes,
	}
}

func makeTBF(tbs *TokenBucketState, linkIndex int) (*netlink.Tbf, error) {
	if tbs.Rate == 0 {
		return nil, fmt.Errorf("invalid rate: %d", tbs.Rate)
	}
	if tbs.Buffer == 0 {
		return nil, fmt.Errorf("invalid burst: %d", tbs.Buffer)
	}

	qdisc := &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Limit:  tbs.Limit,
		Rate:   tbs.Rate,
		Buffer: tbs.Buffer,
	}

	if qdisc.Limit <= 0 || qdisc.Rate <= 0 || qdisc.Buffer <= 0 {
		return nil, fmt.Errorf("invalid value(s) for qdisc %+v, limit: %v, rate %v, buffer %v, verify bandwidth and burst configuration", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer)
	}

	log.Debugf("create TBF qdisc %+v, limit: %v, rate %v, buffer %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer)

	return qdisc, nil
}

func createTBF(tbs *TokenBucketState, linkIndex int) error {
	// Equivalent to
	// tc qdisc add dev link root tbf

	qdisc, err := makeTBF(tbs, linkIndex)
	if err != nil {
		return fmt.Errorf("get TBF qdisc %+v, limit: %v, rate %v, buffer %v: %w", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}

	err = netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("create TBF qdisc %+v, limit: %v, rate %v, buffer %v: %w", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}
	return nil
}

func updateTBF(tbs *TokenBucketState, linkIndex int) error {
	// Equivalent to
	// tc qdisc change dev link root tbf

	qdisc, err := makeTBF(tbs, linkIndex)
	if err != nil {
		return fmt.Errorf("get TBF qdisc %+v, limit: %v, rate %v, buffer %v: %w", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}

	err = netlink.QdiscChange(qdisc)
	if err != nil {
		return fmt.Errorf("update TBF qdisc %+v, limit: %v, rate %v, buffer %v: %w", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}
	return nil
}
