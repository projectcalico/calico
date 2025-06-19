// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

func TestConnectionAllowedCTFull(t *testing.T) {
	RegisterTestingT(t)

	resetBPFMaps()

	hostIP := net.IPv4(1, 1, 1, 1)
	hostPort := uint16(666)

	srcPort := uint16(12345)

	defer func() {
		// Disable debug while cleaning up the maps
		logrus.SetLevel(logrus.WarnLevel)
		cleanUpMaps()
	}()

	// Disable debug while filling up the map
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	val := conntrack.NewValueNormal(0, 0, conntrack.Leg{}, conntrack.Leg{})

	var err error

	for i := 1; i <= ctMap.Size(); i++ {
		srcIP := net.IPv4(10, byte((i&0xff0000)>>16), byte((i&0xff00)>>8), byte(i&0xff))

		key := conntrack.NewKey(1, srcIP, srcPort, hostIP, hostPort)
		err = ctMap.Update(key[:], val[:])
		Expect(err).NotTo(HaveOccurred())
	}

	// re-enable debug
	logrus.SetLevel(loglevel)

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	destCIDR := net.IPNet{
		IP:   ipv4.DstIP,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}

	defer resetRTMap(rtMap)
	defer func() { bpfIfaceName = "" }()

	// With lru, we will able to create the entry and the packet must be allowed.
	bpfIfaceName = "ctNO"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	// Destination is a local workload - should pass
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "ctLW"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

}
