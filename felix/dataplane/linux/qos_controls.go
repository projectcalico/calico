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
	"net"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/proto"
)

func (m *endpointManager) maybeUpdateQoSBandwidth(old, new *proto.WorkloadEndpoint) error {
	var errs []error

	var oldName, newName string

	if old != nil {
		oldName = old.Name
	}
	if new != nil {
		newName = new.Name
	}

	if old != nil && (oldName != newName) {
		// Interface name changed, or workload removed.  Remove ingress QoS, if present,
		// from the old workload interface.
		oldIngress, err := ReadIngressQdisc(oldName)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading ingress qdisc from workload %s: %v", oldName, err))
		}
		if oldIngress != nil {
			err := RemoveIngressQdisc(oldName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing ingress qdisc from workload %s: %v", oldName, err))
			}
		}
		oldEgress, err := ReadEgressQdisc(oldName)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading egress qdisc from workload %s: %v", oldName, err))
		}
		if oldEgress != nil {
			err := RemoveEgressQdisc(oldName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing egress qdisc from workload %s: %v", oldName, err))
			}
		}
	}

	// Now we are only concerned with the new workload interface.
	if new != nil {
		// Work out what we QoS we want.
		var desiredIngress, desiredEgress *TokenBucketState
		if new.QosControls != nil {
			if new.QosControls.IngressBandwidth != 0 {
				desiredIngress = GetTBFValues(uint64(new.QosControls.IngressBandwidth), uint64(new.QosControls.IngressBurst))
			}
			if new.QosControls.EgressBandwidth != 0 {
				desiredEgress = GetTBFValues(uint64(new.QosControls.EgressBandwidth), uint64(new.QosControls.EgressBurst))
			}
		}

		// Read what QoS is currently set on the interface.
		currentIngress, err := ReadIngressQdisc(newName)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading ingress qdisc from workload %s: %v", newName, err))
		}
		currentEgress, err := ReadEgressQdisc(newName)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading egress qdisc from workload %s: %v", newName, err))
		}

		if currentIngress == nil && desiredIngress != nil {
			// Add.
			err := CreateIngressQdisc(desiredIngress, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding ingress qdisc to workload %s: %v", newName, err))
			}
		} else if currentIngress != nil && desiredIngress == nil {
			// Remove.
			err := RemoveIngressQdisc(newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing ingress qdisc from workload %s: %v", newName, err))
			}
		} else if !currentIngress.Equals(desiredIngress) {
			// Update.
			err := UpdateIngressQdisc(desiredIngress, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error changing ingress qdisc on workload %s: %v", newName, err))
			}
		}

		if currentEgress == nil && desiredEgress != nil {
			// Add.
			err := AddEgressQdisc(desiredEgress, newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error adding egress qdisc to workload %s: %v", newName, err))
			}
		} else if currentEgress != nil && desiredEgress == nil {
			// Remove.
			err := RemoveEgressQdisc(newName)
			if err != nil {
				errs = append(errs, fmt.Errorf("error removing egress qdisc from workload %s: %v", newName, err))
			}
		} else if !currentEgress.Equals(desiredEgress) {
			// Update.
			err := UpdateEgressQdisc(desiredEgress, GetIfbDeviceName(newName))
			if err != nil {
				errs = append(errs, fmt.Errorf("error changing egress qdisc on workload %s: %v", newName, err))
			}
		}
	}

	return errors.Join(errs...)
}

type TokenBucketState struct {
	Rate   uint64
	Buffer uint32
	Limit  uint32
}

func (s *TokenBucketState) Equals(other *TokenBucketState) bool {
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
		return fmt.Errorf("Failed to get link: %v", err)
	}

	qdiscs, err := SafeQdiscList(link)
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
	ifbDeviceName := GetIfbDeviceName(intf)

	if err := TeardownIfb(ifbDeviceName); err != nil {
		return fmt.Errorf("Failed to tear down ifb device %s: %v", ifbDeviceName, err)
	}

	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("Failed to get link: %v", err)
	}

	qdiscs, err := SafeQdiscList(link)
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

func ReadIngressQdisc(intf string) (*TokenBucketState, error) {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return nil, fmt.Errorf("Failed to get link %s: %v", intf, err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("Failed to list qdiscs on link %s: %v", intf, err)
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
		return nil, fmt.Errorf("Failed to get link %s: %v", ifbDeviceName, err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("Failed to list qdiscs on link %s: %v", ifbDeviceName, err)
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
	err = createTBF(tbs, ifbDevice.Attrs().Index)
	if err != nil {
		return fmt.Errorf("create ifb qdisc on dev %s: %v", ifbDeviceName, err)
	}
	return nil
}

func UpdateEgressQdisc(tbs *TokenBucketState, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device %s: %v", ifbDeviceName, err)
	}
	return updateTBF(tbs, ifbDevice.Attrs().Index)
}

func GetTBFValues(rateInBits, burstInBits uint64) *TokenBucketState {
	rateInBytes := rateInBits / 8
	burstInBytes := burstInBits / 8
	bufferInBytes := buffer(uint64(rateInBytes), uint32(burstInBytes))
	latency := latencyInUsec(latencyInMillis)
	limitInBytes := limit(uint64(rateInBytes), latency, uint32(burstInBytes))

	return &TokenBucketState{
		Rate:   rateInBytes,
		Buffer: bufferInBytes,
		Limit:  limitInBytes,
	}
}

func makeTBF(tbs *TokenBucketState, linkIndex int) (*netlink.Tbf, error) {
	// Equivalent to
	// tc qdisc add dev link root tbf
	//		rate netConf.BandwidthLimits.Rate
	//		burst netConf.BandwidthLimits.Burst
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
		return fmt.Errorf("get TBF qdisc %+v, limit: %v, rate %v, buffer %v: %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}

	err = netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("create TBF qdisc %+v, limit: %v, rate %v, buffer %v: %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, err)
	}
	return nil
}

func updateTBF(tbs *TokenBucketState, linkIndex int) error {
	// Equivalent to
	// tc qdisc change dev link root tbf

	qdisc, err := makeTBF(tbs, linkIndex)
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
