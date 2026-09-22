// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package commands

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestProtoFromString(t *testing.T) {
	RegisterTestingT(t)

	for name, expected := range map[string]uint8{
		"tcp":    6,
		"TCP":    6,
		"udp":    17,
		"icmp":   1,
		"icmp6":  58,
		"icmpv6": 58,
		"sctp":   132,
		"132":    132,
		"0":      0,
		"255":    255,
	} {
		proto, err := protoFromString(name)
		Expect(err).NotTo(HaveOccurred(), "protocol %q", name)
		Expect(proto).To(Equal(expected), "protocol %q", name)
	}

	for _, name := range []string{"", "any", "-1", "256", "0x84", "nonsense"} {
		_, err := protoFromString(name)
		Expect(err).To(HaveOccurred(), "protocol %q", name)
	}
}

func TestProtoStr(t *testing.T) {
	RegisterTestingT(t)

	Expect(protoStr(6)).To(Equal("TCP"))
	Expect(protoStr(17)).To(Equal("UDP"))
	Expect(protoStr(1)).To(Equal("ICMP"))
	Expect(protoStr(58)).To(Equal("ICMP6"))
	Expect(protoStr(132)).To(Equal("SCTP"))
	Expect(protoStr(47)).To(Equal("Proto-47"))
}

func TestConntrackRemoveArgs(t *testing.T) {
	RegisterTestingT(t)

	parse := func(args ...string) (*conntrackRemoveCmd, error) {
		cmd := &conntrackRemoveCmd{Command: newConntrackRemoveCmd()}
		return cmd, cmd.Args(cmd.Command, args)
	}

	cmd, err := parse("sctp", "10.0.0.1", "10.0.0.2")
	Expect(err).NotTo(HaveOccurred())
	Expect(cmd.proto).To(Equal(uint8(132)))
	Expect(cmd.anyProto).To(BeFalse())
	Expect(cmd.ip1.String()).To(Equal("10.0.0.1"))
	Expect(cmd.ip2.String()).To(Equal("10.0.0.2"))

	cmd, err = parse("132", "10.0.0.1", "10.0.0.2")
	Expect(err).NotTo(HaveOccurred())
	Expect(cmd.proto).To(Equal(uint8(132)))

	cmd, err = parse("any", "fd00::1", "fd00::2")
	Expect(err).NotTo(HaveOccurred())
	Expect(cmd.anyProto).To(BeTrue())
	Expect(cmd.ip1.String()).To(Equal("fd00::1"))

	_, err = parse("nonsense", "10.0.0.1", "10.0.0.2")
	Expect(err).To(MatchError(ContainSubstring("unknown protocol nonsense")))

	_, err = parse("tcp", "notanip", "10.0.0.2")
	Expect(err).To(MatchError(ContainSubstring("is not an ip")))
}
