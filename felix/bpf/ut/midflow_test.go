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

	//tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/nat"
)

func TestMidflowFailoverNoConntrack(t *testing.T) {
	RegisterTestingT(t)
	resetBPFMaps()
	var err error

	// We are going to pretend to have a ConsistentHash-enabled NodePort
	// on this machine.
	hostIP := net.IPv4(1, 1, 1, 1)
	hostPort := uint16(666)

	defer func() {
		// Disable debug while cleaning up the maps
		logrus.SetLevel(logrus.WarnLevel)
		cleanUpMaps()
	}()

	// Disable debug while filling up maps.
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	var svcKey nat.FrontendKeyInterface = nat.NewNATKey(hostIP, hostPort, 6)
	var svcVal nat.FrontendValue = nat.NewNATValue(123, 1, 0, 0)
	err = natMap.Update(svcKey.AsBytes(), svcVal.AsBytes())
	Expect(err).NotTo(HaveOccurred())

	// re-enable debug
	logrus.SetLevel(loglevel)

	_, _, _, _, packetBytes, err := testPacketV4(
		nil,
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IPv4(1, 2, 3, 4),
			DstIP:    net.IPv4(1, 1, 1, 1),
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort:    54321,
			DstPort:    7890,
			SYN:        false,
			DataOffset: 5,
		},
		nil)
	Expect(err).NotTo(HaveOccurred())

	defer resetRTMap(rtMap)
	defer func() { bpfIfaceName = "" }()

	// With lru, we will able to create the entry and the packet must be allowed.
	bpfIfaceName = "mf00"
	//skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Destination is a local workload - should pass
		res, err := bpfrun(packetBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
}
