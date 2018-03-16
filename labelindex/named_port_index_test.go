// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package labelindex_test

import (
	. "github.com/projectcalico/felix/labelindex"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"net"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

var _ = Describe("SelectorAndNamedPortIndex", func() {
	var uut *SelectorAndNamedPortIndex
	var recorder *testRecorder

	BeforeEach(func() {
		uut = NewSelectorAndNamedPortIndex()
		recorder = &testRecorder{ipsets: make(map[string]map[IPSetMember]bool)}
		uut.OnMemberAdded = recorder.OnMemberAdded
		uut.OnMemberRemoved = recorder.OnMemberRemoved
	})

	Describe("NetworkSet CIDRs", func() {
		It("should include equivalent CIDRs only once", func() {
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.NetworkSetKey{Name: "blinky"},
					Value: &model.NetworkSet{
						Nets: []calinet.IPNet{
							{net.IPNet{
								IP:   net.IP{192, 168, 4, 10},
								Mask: net.IPMask{255, 255, 0, 0},
							}},
						},
						Labels: map[string]string{"villain": "ghost"},
					},
				},
			})
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.NetworkSetKey{Name: "inky"},
					Value: &model.NetworkSet{
						Nets: []calinet.IPNet{
							{net.IPNet{
								IP:   net.IP{192, 168, 20, 1},
								Mask: net.IPMask{255, 255, 0, 0},
							}},
						},
						Labels: map[string]string{"villain": "ghost"},
					},
				},
			})
			s, err := selector.Parse("villain == 'ghost'")
			Expect(err).ToNot(HaveOccurred())
			uut.UpdateIPSet("villains", s, ProtocolNone, "")
			set, ok := recorder.ipsets["villains"]
			Expect(ok).To(BeTrue())
			Expect(set).To(HaveLen(1))
		})
	})
})

type testRecorder struct {
	ipsets map[string]map[IPSetMember]bool
}

func (t *testRecorder) OnMemberAdded(ipSetID string, member IPSetMember) {
	s := t.ipsets[ipSetID]
	if s == nil {
		s = make(map[IPSetMember]bool)
		t.ipsets[ipSetID] = s
	}
	s[member] = true
}

func (t *testRecorder) OnMemberRemoved(ipSetID string, member IPSetMember) {
	s := t.ipsets[ipSetID]
	delete(s, member)
	if len(s) == 0 {
		delete(t.ipsets, ipSetID)
	}
}
