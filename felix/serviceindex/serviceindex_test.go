// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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

package serviceindex_test

import (
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/labelindex"
	. "github.com/projectcalico/calico/felix/serviceindex"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("ServiceIndex", func() {
	var idx *ServiceIndex
	var recorder *testRecorder

	BeforeEach(func() {
		idx = NewServiceIndex()
		recorder = &testRecorder{ipsets: make(map[string]map[labelindex.IPSetMember]bool)}
		idx.OnMemberAdded = recorder.OnMemberAdded
		idx.OnMemberRemoved = recorder.OnMemberRemoved
	})

	It("should handle a Service being made active, then inactive", func() {
		p := int32(80)
		proto := v1.ProtocolTCP
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.1"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &proto,
						},
					},
				},
			},
		})

		// Not yet active, so ipset membership should be empty.
		Expect(recorder.ipsets).To(Equal(map[string]map[labelindex.IPSetMember]bool{}))

		// Make it active.
		idx.UpdateIPSet("identifier", "default/svc1")
		set, ok := recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(1))

		// Service is no longer active.
		idx.DeleteIPSet("identifier")
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))
	})

	It("should handle creation and deletion of an EndpointSlice", func() {
		// Make the service active, simulating a policy with a Service egress rule matching this node.
		// We have no endpoints yet, so no state should change.
		idx.UpdateIPSet("identifier", "default/svc1")
		set, ok := recorder.ipsets["identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))

		// Add an IP set for the service again, this time simulating a policy with a Service ingress rule.
		// We have no endpoints yet, so no state should change.
		idx.UpdateIPSet("svcnoport,identifier", "default/svc1")
		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))

		// Send an EndpointSlice for the now active service.
		p := int32(80)
		proto := v1.ProtocolTCP
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.1"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &proto,
						},
					},
				},
			},
		})

		// We should now get IP set members added.
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(1))

		// We should get IP set members also added to the IP set for ingress rules (without ports).
		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(1))

		// Remove the EndpointSlice, thus removing the IP set members.
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: nil,
			},
		})
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))
		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))

		// Remove the endpoint slice a second time, to make sure we handle deletion for a slice we don't know about.
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: nil,
			},
		})
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))
		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))
	})

	It("should handle an endpoint slice with multiple ports and protocols", func() {
		p := int32(80)
		tcp := v1.ProtocolTCP
		udp := v1.ProtocolUDP
		sctp := v1.ProtocolSCTP
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.1", "10.0.0.2"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &tcp,
						},
						{
							Port:     &p,
							Protocol: &udp,
						},
						{
							Port:     &p,
							Protocol: &sctp,
						},
					},
				},
			},
		})

		// Not yet active, so ipset membership should be empty.
		Expect(recorder.ipsets).To(Equal(map[string]map[labelindex.IPSetMember]bool{}))

		// Make it active. We should have 6 IP set members - one for each address / port combintation.
		idx.UpdateIPSet("identifier", "default/svc1")
		set, ok := recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(6))

		// Create an IP set with no ports. It should have 2 IP set members - one for each address
		idx.UpdateIPSet("svcnoport,identifier", "default/svc1")
		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(2))

		// Service is no longer active.
		idx.DeleteIPSet("identifier")
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))
	})

	// This test simulates a scenario where an endpoint moves from one endpoint slice to another,
	// temporarily double-counting the endpoint. The index should treat this as a single IP set member.
	It("should handle transient overlapping endpoint slices", func() {
		// Make the service active, simulating a policy with a Service egress rule matching this node.
		// We have no endpoints yet, so no state should change.
		idx.UpdateIPSet("identifier", "default/svc1")
		set, ok := recorder.ipsets["identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))

		// Simulate a policy with a Service ingress rule.
		// We have no endpoints yet, so no state should change.
		idx.UpdateIPSet("svcnoport,identifier", "default/svc1")
		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeFalse())
		Expect(set).To(HaveLen(0))

		// Send an EndpointSlice for the now active service with two endpoints.
		p := int32(80)
		proto := v1.ProtocolTCP
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.1"},
						},
						{
							Addresses: []string{"10.0.0.2"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &proto,
						},
					},
				},
			},
		})

		// We should now get IP set members added.
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(2))

		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(2))

		// Send an EndpointSlice that overlaps with the first one. It shares one endpoint, and also includes
		// an additional endpoint not in the original.
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep2", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.1"},
						},
						{
							Addresses: []string{"10.0.0.3"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &proto,
						},
					},
				},
			},
		})

		// We should get one more IP set member added for the non-overlapping endpoint.
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(3))

		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(3))

		// Remove the overlapping endpoint from the first endpoint slice, completing the move.
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep1", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.2"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &proto,
						},
					},
				},
			},
		})

		// Should be no change in the number of IP set members.
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(3))

		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(3))

		// Remove the endpoint from the second slice as well, which should decref to zero and thus
		// remove it from IP set membership.
		idx.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Name: "ep2", Namespace: "default", Kind: "KubernetesEndpointSlice"},
				Value: &discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ep2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc1",
						},
					},
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"10.0.0.3"},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Port:     &p,
							Protocol: &proto,
						},
					},
				},
			},
		})

		// Should now only have 2 endpoints, as the overlapping endpoint has been
		// removed from both slices.
		set, ok = recorder.ipsets["identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(2))

		set, ok = recorder.ipsets["svcnoport,identifier"]
		Expect(ok).To(BeTrue())
		Expect(set).To(HaveLen(2))
	})

})

type testRecorder struct {
	ipsets map[string]map[labelindex.IPSetMember]bool
}

func (t *testRecorder) OnMemberAdded(ipSetID string, member labelindex.IPSetMember) {
	s := t.ipsets[ipSetID]
	if s == nil {
		s = make(map[labelindex.IPSetMember]bool)
		t.ipsets[ipSetID] = s
	}
	s[member] = true
}

func (t *testRecorder) OnMemberRemoved(ipSetID string, member labelindex.IPSetMember) {
	s := t.ipsets[ipSetID]
	delete(s, member)
	if len(s) == 0 {
		delete(t.ipsets, ipSetID)
	}
}
