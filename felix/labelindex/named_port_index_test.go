// Copyright (c) 2016-2022 Tigera, Inc. All rights reserved.

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
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/labelindex"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"net"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
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
							{IPNet: net.IPNet{
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
							{IPNet: net.IPNet{
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

	Describe("NetworkSet profiles", func() {
		It("should inherit labels from profiles", func() {
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindProfile, Name: "doo"},
					Value: &v3.Profile{
						Spec: v3.ProfileSpec{
							LabelsToApply: map[string]string{"superhero": "scooby"},
						},
					},
				},
			})
			uut.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.NetworkSetKey{Name: "scary-ns"},
					Value: &model.NetworkSet{
						Nets: []calinet.IPNet{
							{IPNet: net.IPNet{
								IP:   net.IP{192, 168, 20, 1},
								Mask: net.IPMask{255, 255, 0, 0},
							}},
						},
						Labels:     map[string]string{"villain": "ghost"},
						ProfileIDs: []string{"doo"},
					},
				},
			})
			s, err := selector.Parse("villain == 'ghost' && superhero == 'scooby'")
			Expect(err).ToNot(HaveOccurred())
			uut.UpdateIPSet("scoobydoobydoo", s, ProtocolNone, "")
			set, ok := recorder.ipsets["scoobydoobydoo"]
			Expect(ok).To(BeTrue())
			Expect(set).To(HaveLen(1))
		})
	})
	Describe("HostEndpoint CIDRs", func() {
		It("should update IP sets for labels with empty values", func() {
			hep := &model.HostEndpoint{
				Name:              "eth0",
				ExpectedIPv4Addrs: []calinet.IP{calinet.MustParseIP("1.2.3.4")},
				ExpectedIPv6Addrs: []calinet.IP{calinet.MustParseIP("aa:bb::cc:dd")},
				Labels: map[string]string{
					"label2": "",
				},
				ProfileIDs: []string{"profile1"},
			}
			hepKVP := model.KVPair{
				Key:   model.HostEndpointKey{Hostname: "127.0.0.1", EndpointID: "hosta.eth0-a"},
				Value: hep,
			}
			uut.OnUpdate(api.Update{KVPair: hepKVP})
			s, err := selector.Parse("has(label2)")
			Expect(err).ToNot(HaveOccurred())

			// The new ipset should have 2 IPs.
			uut.UpdateIPSet("heptest", s, ProtocolNone, "")
			set, ok := recorder.ipsets["heptest"]
			Expect(ok).To(BeTrue())
			Expect(set).To(HaveLen(2))

			// Update the hostendpoint labels so they are not matched by the
			// selector.
			hep.Labels = map[string]string{
				"label1": "value1",
			}
			uut.OnUpdate(api.Update{KVPair: hepKVP})

			// Expect the ipset to be empty (OnMemberRemoved will have been
			// called twice.)
			set, ok = recorder.ipsets["heptest"]
			Expect(ok).To(BeFalse())
			Expect(set).To(HaveLen(0))
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
