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

	"github.com/projectcalico/calico/felix/bpf/nat"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestMidflowFailoverNoConntrack(t *testing.T) {
	RegisterTestingT(t)
	resetBPFMaps()
	var err error

	loglevel := logrus.GetLevel()
	defer withLogLevelWarnDo(cleanUpMaps)
	defer func() { bpfIfaceName = "" }()
	defer logrus.SetLevel(loglevel)

	// A mock service IP.
	hostIP := net.IPv4(1, 1, 1, 1)
	hostPort := uint16(666)
	svcKey := nat.NewNATKey(hostIP, hostPort, 6)
	svcVal := nat.NewNATValue(123, 1, 0, 0)

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.IPv4(1, 2, 3, 4),
		DstIP:    hostIP,
		Protocol: layers.IPProtocolTCP,
	}

	connLayer := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        false,
		DataOffset: 5,
	}

	withLogLevelWarnDo(func() {
		err = natMap.Update(svcKey.AsBytes(), svcVal.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	})

	_, _, _, _, packetBytes, err := testPacketV4(nil, ipLayer, connLayer, nil)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "mf00"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Destination is a remote workload, but pkt is midflow, and a conntrack miss.
		// Not a ConsistentHash-enabled packet; Should allow pkt to fallthrough to *tables.
		res, err := bpfrun(packetBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
		Expect(skbMark).To(BeEquivalentTo(tcdefs.MarkSeenFallThrough))
	})

	svcVal = nat.NewNATValueWithFlags(123, 1, 0, 0, nat.NATFlgConsistentHash)
	withLogLevelWarnDo(func() {
		resetMap(natMap)
		err = natMap.Update(svcKey.AsBytes(), svcVal.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Same as before but now, pkt belongs to a ConsistentHash service.
		// Should attempt to tunnel to the destination.
		_, err := bpfrun(packetBytes)
		Expect(err).NotTo(HaveOccurred())
	})
}

func withLogLevelWarnDo(f func()) {
	// Disable debug while filling up maps.
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)
	f()
}
