// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/filter"
)

func TestFilter(t *testing.T) {
	RegisterTestingT(t)

	_, _, _, _, bytes, _ := testPacketV4(
		&layers.Ethernet{
			SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
			DstMAC:       []byte{0, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IPv4(1, 2, 3, 4),
			DstIP:    net.IPv4(11, 22, 33, 44),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 1234,
			DstPort: 666,
		},
		make([]byte, 36),
	)

	type testCase struct {
		expression string
		match      bool
	}

	tests := []testCase{
		// L2
		{"ip", true},
		{"ip6", false},
		{"ip and tcp", false},
		// L2 + L3
		{"", true},
		{"udp", true},
		{"host 1.2.3.4 or host 5.6.7.8", true},
		{"host 1.2.3.4 and host 5.6.7.8", false},
		{"src 1.2.3.4 and dst 11.22.33.44", true},
		{"dst 1.2.3.4 and src 11.22.33.44", false},
		{"(host 1.2.3.4 or host 5.6.7.8) and (udp port 666)", true},
		{"(host 1.2.3.4 or host 5.6.7.8) and (udp port 1212)", false},
		{"len >= 64", true},
		{"len < 64", false},
		{"len >= 500", false},
		{"portrange 600-700", true},
		{"tcp portrange 600-700", false},
		{"portrange 700-800", false},
	}

	links := []struct {
		level string
		typ   layers.LinkType
		data  []byte
		tests []testCase
	}{
		{"L2", layers.LinkTypeEthernet, bytes, tests},
		{"L3", layers.LinkTypeIPv4, bytes[14:], tests[3:]},
	}

	for _, link := range links {
		for _, tc := range link.tests {
			t.Run(link.level+"_"+tc.expression, func(t *testing.T) {

				insns, err := filter.NewStandAlone(link.typ, 64, tc.expression)
				Expect(err).NotTo(HaveOccurred())
				fd, err := bpf.LoadBPFProgramFromInsns(insns, "filter", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
				Expect(err).NotTo(HaveOccurred())
				Expect(fd).NotTo(BeZero())
				defer func() {
					Expect(fd.Close()).NotTo(HaveOccurred())
				}()

				rc, err := bpf.RunBPFProgram(fd, link.data, 1)
				Expect(err).NotTo(HaveOccurred())
				erc := -1
				if !tc.match {
					erc = 2
				}
				Expect(rc.RC).To(BeNumerically("==", erc))
			})
		}
	}

	link := links[0]

	for _, tc := range link.tests {
		if tc.expression == "" {
			continue
		}

		neg := "not ( " + tc.expression + " )"

		t.Run(link.level+"_"+neg, func(t *testing.T) {

			insns, err := filter.NewStandAlone(layers.LinkTypeEthernet, 64, neg)
			Expect(err).NotTo(HaveOccurred())
			fd, err := bpf.LoadBPFProgramFromInsns(insns, "filter", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
			Expect(err).NotTo(HaveOccurred())
			Expect(fd).NotTo(BeZero())
			defer func() {
				Expect(fd.Close()).NotTo(HaveOccurred())
			}()

			rc, err := bpf.RunBPFProgram(fd, link.data, 1)
			Expect(err).NotTo(HaveOccurred())
			erc := 2
			if !tc.match {
				erc = -1
			}
			Expect(rc.RC).To(BeNumerically("==", erc))
		})
	}
}
