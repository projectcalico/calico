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

package ut_test

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/proto"
)

// The destination is the pod itself, so only the pod reaching itself gets action; anything else gets other.
func rulesFromSelf(action, other string) *polprog.Rules {
	return &polprog.Rules{
		SuppressNormalHostPolicy: true,
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "self",
				Rules: []polprog.Rule{
					{Rule: &proto.Rule{Action: action, SrcNet: []string{dstV4CIDR.String()}}},
					{Rule: &proto.Rule{Action: other}},
				},
			}},
		}},
	}
}

// A pod reaching itself via a service arrives MASQed from the host; to-WEP polices it by the pod's address.
func TestMASQToSelfIsPoliced(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	hostIP = node1ip

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	Expect(rtMap.Update(routes.NewKey(srcV4CIDR).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes())).NotTo(HaveOccurred())
	Expect(rtMap.Update(routes.NewKey(dstV4CIDR).AsBytes(),
		routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes())).NotTo(HaveOccurred())

	for _, c := range []struct {
		name   string
		rules  *polprog.Rules
		retval int
	}{
		{"policy denies the pod itself", rulesFromSelf("Deny", "Allow"), resTC_ACT_SHOT},
		{"policy allows the pod itself", rulesFromSelf("Allow", "Deny"), resTC_ACT_UNSPEC},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetCTMap(ctMap)
			skbMark = tcdefs.MarkSeenMASQ
			runBpfTest(t, "calico_to_workload_ep", c.rules, func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(res.Retval).To(Equal(c.retval))
			})
		})
	}
}
