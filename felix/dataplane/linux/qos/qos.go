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

// Calico enforces bandwidth limits with token bucket filters (TBFs) on the cali... or
// tap... workload interface.
//
// For the "ingress" direction, i.e. traffic TO the workload, Calico creates a TBF qdisc (queuing
// discipline) directly on the workload interface.
//
// For the "egress" direction, i.e. traffic FROM the workload, Calico creates an "ingress" qdisc on
// the workload interface, with a u32 filter that redirects all packets to an "IFB" interface, and then
// also creates a TBF qdisc on the IFB interface.
//
// Why is that latter called an "ingress" qdisc, but Calico uses it for "egress" traffic?
// https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.adv-qdisc.ingress.html says:
//
// "All qdiscs discussed so far are egress qdiscs. Each interface however can also have an ingress
// qdisc which is not used to send packets out to the network adaptor. Instead, it allows you to
// apply tc filters to packets coming in over the interface, regardless of whether they have a local
// destination or are to be forwarded.
//
// In other words Linux means "ingress" as in "coming _into_ the generic kernel code from a network
// adaptor".  In the Calico workload case, for workload egress traffic, this equates to "after
// passing through the workload interface". The u32 filter on that "ingress" qdisc then redirects
// to another interface - the IFB device - and a TBF is imposed on the traffic as it goes _to_ that
// IFB device.
//
// (Fundamentally, a TBF only works on traffic that the kernel is sending _to_ a network device.
// Hence for workload ingress we can place a TBF directly on the workload interface, but for
// workload egress we have to use a redirect step so that there's another interface involved for the
// kernel to send traffic to.)

package qos

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type TokenBucketState struct {
	Rate     uint64
	Buffer   uint32
	Limit    uint32
	Peakrate uint64
	Minburst uint32
}

func (s *TokenBucketState) Equals(other *TokenBucketState) bool {
	if s == nil && other == nil {
		return true
	}
	if (s == nil && other != nil) || (s != nil && other == nil) {
		return false
	}
	return s.Rate == other.Rate && s.Buffer == other.Buffer && s.Limit == other.Limit && s.Peakrate == other.Peakrate && s.Minburst == other.Minburst
}

func AddEgressQdisc(tbs *TokenBucketState, intf string) error {
	mtu, err := GetMTU(intf)
	if err != nil {
		return fmt.Errorf("Failed to get MTU for interface %s: %w", intf, err)
	}

	ifbDeviceName := GetIfbDeviceName(intf)

	err = CreateIfb(ifbDeviceName, mtu)
	if err != nil {
		return fmt.Errorf("Failed to create ifb device %s: %w", ifbDeviceName, err)
	}

	return CreateEgressQdisc(tbs, intf, ifbDeviceName)
}

func RemoveIngressQdisc(intf string) error {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return fmt.Errorf("Failed to get link: %w", err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs: %w", err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if isTbf {
			err := netlink.QdiscDel(tbf)
			if err != nil {
				return fmt.Errorf("Failed to delete qdisc: %w", err)
			}
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

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs: %w", err)
	}

	for _, qdisc := range qdiscs {
		ingress, isIngress := qdisc.(*netlink.Ingress)
		if isIngress {
			err := netlink.QdiscDel(ingress)
			if err != nil {
				return fmt.Errorf("Failed to delete qdisc: %w", err)
			}
		}
	}

	return nil
}

func ReadIngressQdisc(intf string) (*TokenBucketState, error) {
	link, err := netlink.LinkByName(intf)
	if err != nil {
		return nil, fmt.Errorf("Failed to get link %s: %w", intf, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("Failed to list qdiscs on link %s: %w", intf, err)
	}

	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		if isTbf {
			return &TokenBucketState{Rate: tbf.Rate, Buffer: tbf.Buffer, Limit: tbf.Limit, Peakrate: tbf.Peakrate, Minburst: tbf.Minburst}, nil
		}
	}

	return nil, nil
}

func ReadEgressQdisc(intf string) (*TokenBucketState, error) {
	ifbDeviceName := GetIfbDeviceName(intf)

	link, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to get link %s: %w", ifbDeviceName, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("Failed to list qdiscs on link %s: %w", ifbDeviceName, err)
	}

	tbs := &TokenBucketState{}
	for _, qdisc := range qdiscs {
		tbf, isTbf := qdisc.(*netlink.Tbf)
		// TBF info may be split in multiple netlink messages, loop through them to populate TokenBucketState
		if isTbf {
			if tbf.Rate > 0 {
				tbs.Rate = tbf.Rate
			}
			if tbf.Buffer > 0 {
				tbs.Buffer = tbf.Buffer
			}
			if tbf.Limit > 0 {
				tbs.Limit = tbf.Limit
			}
			if tbf.Peakrate > 0 {
				tbs.Peakrate = tbf.Peakrate
			}
			if tbf.Minburst > 0 {
				tbs.Minburst = tbf.Minburst
			}
		}
	}

	return tbs, nil
}

const maxIfbDeviceLength = 15
const ifbDevicePrefix = "bwcali"

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

const latencyMillis = 25

func CreateIfb(ifbDeviceName string, mtu int) error {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = ifbDeviceName
	linkAttrs.Flags = net.FlagUp
	linkAttrs.MTU = mtu

	err := netlink.LinkAdd(&netlink.Ifb{
		LinkAttrs: linkAttrs,
	})

	if err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("adding link %s: %w", ifbDeviceName, err)
		}
	}

	return nil
}

func TeardownIfb(deviceName string) error {
	err := ip.DelLinkByName(deviceName)
	if err != nil {
		if err == ip.ErrLinkNotFound {
			return nil
		}
		return fmt.Errorf("tearing down link %s: %w", deviceName, err)
	}

	return nil
}

func CreateIngressQdisc(tbs *TokenBucketState, workloadDeviceName string) error {
	workloadDevice, err := netlink.LinkByName(workloadDeviceName)
	if err != nil {
		return fmt.Errorf("get host device %s: %w", workloadDeviceName, err)
	}
	return createTBF(tbs, workloadDevice)
}

func UpdateIngressQdisc(tbs *TokenBucketState, workloadDeviceName string) error {
	workloadDevice, err := netlink.LinkByName(workloadDeviceName)
	if err != nil {
		return fmt.Errorf("get host device %s: %w", workloadDeviceName, err)
	}
	return updateTBF(tbs, workloadDevice)
}

func CreateEgressQdisc(tbs *TokenBucketState, workloadDeviceName string, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device %s: %w", ifbDeviceName, err)
	}
	workloadDevice, err := netlink.LinkByName(workloadDeviceName)
	if err != nil {
		return fmt.Errorf("get host device %s: %w", workloadDeviceName, err)
	}

	// check if host device has a ingress qdisc
	var qdisc *netlink.Ingress
	qdiscList, err := netlink.QdiscList(workloadDevice)
	if err != nil {
		return fmt.Errorf("Failed to list qdiscs on dev %s: %w", workloadDeviceName, err)
	}

	for _, qd := range qdiscList {
		ingressQd, isIngress := qd.(*netlink.Ingress)
		if isIngress {
			qdisc = ingressQd
			break
		}
	}

	// only add ingress qdisc on host device if it doesn't already exist
	if qdisc == nil {
		qdisc = &netlink.Ingress{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: workloadDevice.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0), // ffff:
				Parent:    netlink.HANDLE_INGRESS,
			},
		}

		err = netlink.QdiscAdd(qdisc)
		if err != nil {
			return fmt.Errorf("create ingress qdisc %+v on dev %s: %w", qdisc, workloadDeviceName, err)
		}
	}

	// List filters on workloadDevice to clean up filters and bandwidth plugin ifb devices (those have a "bwp" prefix), if present.
	filters, err := netlink.FilterList(workloadDevice, netlink.HANDLE_INGRESS)
	if err != nil {
		return fmt.Errorf("list filters on dev %s: %w", workloadDeviceName, err)
	}
	logrus.Debugf("Cleaning up existing filters on dev %s: %+v", workloadDeviceName, filters)
	for _, filter := range filters {
		u32Filter, ok := filter.(*netlink.U32)
		if !ok {
			continue
		}
		for _, action := range u32Filter.Actions {
			mirredAction, ok := action.(*netlink.MirredAction)
			if !ok {
				continue
			}
			logrus.Debugf("Found U32 filter %+v with MirredAction: %+v", u32Filter, mirredAction)
			filterLink, err := netlink.LinkByIndex(mirredAction.Ifindex)
			if err != nil {
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					break
				}
				logrus.Debugf("Failed to get link for ifindex %d on dev %s, error: %v", mirredAction.Ifindex, workloadDeviceName, err)
				continue
			}
			// Remove bandwidth plugin ifb interfaces, or old calico ifb interfaces ('bwcali' prefix but not the current ifbDeviceName)
			if strings.HasPrefix(filterLink.Attrs().Name, "bwp") || (strings.HasPrefix(filterLink.Attrs().Name, "bwcali") && filterLink.Attrs().Name != ifbDeviceName) {
				logrus.Debugf("Cleaning up bandwidth plugin (bwpXXXX) or old calico (bwcaliXXXX) link name %s: %+v", filterLink.Attrs().Name, filterLink)
				err := netlink.LinkDel(filterLink)
				if err != nil {
					if _, ok := err.(netlink.LinkNotFoundError); ok {
						break
					}
					logrus.Debugf("Failed to remove 'bwp' or 'bwcali' ifb link %s, error: %v", filterLink.Attrs().Name, err)
					continue
				}
				break
			}
		}
		err := netlink.FilterDel(filter)
		if err != nil {
			return fmt.Errorf("delete filter %+v on dev %s: %w", filter, workloadDeviceName, err)
		}
	}

	// add filter on host device to mirror traffic to ifb device
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: workloadDevice.Attrs().Index,
			Parent:    qdisc.Attrs().Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId: netlink.MakeHandle(1, 1),
		Actions: []netlink.Action{
			netlink.NewMirredAction(ifbDevice.Attrs().Index),
		},
	}
	err = netlink.FilterAdd(filter)
	if err != nil {
		return fmt.Errorf("add egress filter %+v: %s", filter, err)
	}

	// throttle traffic on ifb device
	err = createTBF(tbs, ifbDevice)
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
	return updateTBF(tbs, ifbDevice)
}

func GetTBFValues(rateBitsPerSec, burstBits, peakrateBitsPerSec uint64, minburstBytes uint32) *TokenBucketState {
	rateBytesPerSec := rateBitsPerSec / 8

	burstBytes := burstBits / 8

	// Time (in usec) it takes to transmit the burst size at the given rate
	timeToBurstUsec := uint32(min(float64(burstBytes)*float64(1000000)/float64(rateBytesPerSec), math.MaxUint32))

	// Buffer size needed to accumulate burst data in-between network scheduler ticks, obtained by multiplying timeToBurstUsec by the number of usec per tick of the network scheduler
	bufferBytes := uint32(min(float64(timeToBurstUsec)*float64(netlink.TickInUsec()), math.MaxUint32))

	latencyUsec := float64(latencyMillis * 1000)

	// Limit for the token bucket, obtained by multiplying the rate (in bytes per sec) by the latency (in sec), then adding the buffer size (in bytes)
	limitBytes := uint32(min(float64(rateBytesPerSec)*latencyUsec/float64(1000000)+float64(bufferBytes), math.MaxUint32))

	var peakrateBytesPerSec uint64

	// If peakrate is defined, calculate its limit (using the same method as above but with peakrate and minburst values)´
	// and use the smallest limit of the two.
	// See https://github.com/iproute2/iproute2/blob/866e1d107b7de68ca1fcd1d4d5ffecf9d96bff30/tc/q_tbf.c#L202
	// to see where the tc command does the same thing.
	if peakrateBitsPerSec != 0 {
		peakrateBytesPerSec = peakrateBitsPerSec / 8

		minburstTimeToBurstUsec := uint32(min(float64(minburstBytes)*float64(1000000)/float64(peakrateBytesPerSec), math.MaxUint32))
		minburstBufferBytes := uint32(min(float64(minburstTimeToBurstUsec)*float64(netlink.TickInUsec()), math.MaxUint32))
		peakrateLimitBytes := uint32(min(float64(peakrateBytesPerSec)*latencyUsec/float64(1000000)+float64(minburstBufferBytes), math.MaxUint32))
		if peakrateLimitBytes < limitBytes {
			limitBytes = peakrateLimitBytes
		}
	}

	return &TokenBucketState{
		Rate:     rateBytesPerSec,
		Buffer:   bufferBytes,
		Limit:    limitBytes,
		Peakrate: peakrateBytesPerSec,
		Minburst: minburstBytes,
	}
}

func makeTBF(tbs *TokenBucketState, workloadDevice netlink.Link) (*netlink.Tbf, error) {
	if tbs == nil || tbs.Limit <= 0 || tbs.Rate <= 0 || tbs.Buffer <= 0 || (tbs.Peakrate == 0 && tbs.Minburst != 0) {
		return nil, fmt.Errorf("invalid value(s) for TokenBucketState %+v, verify bandwidth, burst, peakrate and minburst configuration", tbs)
	}

	// If Peakrate is configured and Minburst is configured to less than the interface MTU, set it to this minimum value
	if tbs.Peakrate > 0 {
		// Set minburst to MTU + 14 bytes (the ethernet hardware header), see
		// https://github.com/torvalds/linux/blob/4a95bc121ccdaee04c4d72f84dbfa6b880a514b6/include/net/pkt_sched.h#L137-L140
		minburst := uint32(workloadDevice.Attrs().MTU) + 14
		if tbs.Minburst < minburst {
			tbs.Minburst = minburst
			logrus.Debugf("make TBF: set minburst to %v", minburst)
		}
	}

	qdisc := &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: workloadDevice.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Limit:    tbs.Limit,
		Rate:     tbs.Rate,
		Buffer:   tbs.Buffer,
		Peakrate: tbs.Peakrate,
		Minburst: tbs.Minburst,
	}

	logrus.Debugf("make TBF qdisc %+v, limit: %v, rate %v, buffer %v, peakrate %v, minburst %v", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, qdisc.Peakrate, qdisc.Minburst)

	return qdisc, nil
}

func createTBF(tbs *TokenBucketState, workloadDevice netlink.Link) error {
	// Equivalent to
	// tc qdisc add dev link root tbf

	qdisc, err := makeTBF(tbs, workloadDevice)
	if err != nil {
		return fmt.Errorf("make TBF qdisc %+v from tbs %+v: %w", qdisc, tbs, err)
	}

	err = netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("add TBF qdisc %+v, limit: %v, rate %v, buffer %v, peakrate %v, minburst %v: %w", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, qdisc.Peakrate, qdisc.Minburst, err)
	}
	return nil
}

func updateTBF(tbs *TokenBucketState, workloadDevice netlink.Link) error {
	// Equivalent to
	// tc qdisc replace dev link root tbf

	qdisc, err := makeTBF(tbs, workloadDevice)
	if err != nil {
		return fmt.Errorf("make TBF qdisc %+v: %w", qdisc, err)
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return fmt.Errorf("change TBF qdisc %+v, limit: %v, rate %v, buffer %v, peakrate %v, minburst %v: %w", qdisc, qdisc.Limit, qdisc.Rate, qdisc.Buffer, qdisc.Peakrate, qdisc.Minburst, err)
	}
	return nil
}
