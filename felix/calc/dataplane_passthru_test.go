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

package calc

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// hostMetaRecorder captures HostMetadata callbacks; other passthru callbacks
// fail the test if called so we don't accidentally cross-pollute scenarios.
type hostMetaRecorder struct {
	updates []hostMetaUpdate
	removes []string
}

type hostMetaUpdate struct {
	hostname string
	ip4Addr  string
	ip6Addr  string
	asnumber string
	labels   map[string]string
}

func (r *hostMetaRecorder) OnHostMetadataUpdate(hostname string, info *HostInfo) {
	r.updates = append(r.updates, hostMetaUpdate{
		hostname: hostname,
		ip4Addr:  info.ip4Addr,
		ip6Addr:  info.ip6Addr,
		asnumber: info.asnumber,
		labels:   info.labels,
	})
}

func (r *hostMetaRecorder) OnHostMetadataRemove(hostname string) {
	r.removes = append(r.removes, hostname)
}

func (r *hostMetaRecorder) OnIPPoolUpdate(model.IPPoolKey, *model.IPPool) {
	Fail("unexpected OnIPPoolUpdate")
}

func (r *hostMetaRecorder) OnIPPoolRemove(model.IPPoolKey) {
	Fail("unexpected OnIPPoolRemove")
}

func (r *hostMetaRecorder) OnServiceAccountUpdate(*proto.ServiceAccountUpdate) {
	Fail("unexpected OnServiceAccountUpdate")
}

func (r *hostMetaRecorder) OnServiceAccountRemove(types.ServiceAccountID) {
	Fail("unexpected OnServiceAccountRemove")
}

func (r *hostMetaRecorder) OnNamespaceUpdate(*proto.NamespaceUpdate) {
	Fail("unexpected OnNamespaceUpdate")
}

func (r *hostMetaRecorder) OnNamespaceRemove(types.NamespaceID) {
	Fail("unexpected OnNamespaceRemove")
}

func (r *hostMetaRecorder) OnWireguardUpdate(string, *model.Wireguard) {
	Fail("unexpected OnWireguardUpdate")
}

func (r *hostMetaRecorder) OnWireguardRemove(string) {
	Fail("unexpected OnWireguardRemove")
}

func (r *hostMetaRecorder) OnGlobalBGPConfigUpdate(*v3.BGPConfiguration) {
	Fail("unexpected OnGlobalBGPConfigUpdate")
}

func (r *hostMetaRecorder) OnServiceUpdate(*proto.ServiceUpdate) {
	Fail("unexpected OnServiceUpdate")
}

func (r *hostMetaRecorder) OnServiceRemove(*proto.ServiceRemove) {
	Fail("unexpected OnServiceRemove")
}

func nodeUpdate(name string, node *internalapi.Node) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:   model.ResourceKey{Name: name, Kind: internalapi.KindNode},
			Value: node,
		},
		UpdateType: api.UpdateTypeKVNew,
	}
}

var _ = Describe("DataplanePassthru host metadata sourcing", func() {
	const host = "host-1"

	var (
		recorder *hostMetaRecorder
		passthru *DataplanePassthru
	)

	BeforeEach(func() {
		recorder = &hostMetaRecorder{}
		passthru = NewDataplanePassthru(recorder, true)
	})

	It("uses BGP IPv4 when supplied", func() {
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				BGP: &internalapi.NodeBGPSpec{IPv4Address: "10.0.0.1/24"},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.1/24"))
		Expect(recorder.updates[0].ip6Addr).To(BeEmpty())
	})

	It("falls back to InternalIP when BGP is nil", func() {
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				Addresses: []internalapi.NodeAddress{
					{Address: "10.0.0.5/24", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.5/24"))
	})

	It("prefers InternalIP over ExternalIP when BGP is nil", func() {
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				Addresses: []internalapi.NodeAddress{
					{Address: "192.0.2.7", Type: internalapi.ExternalIP},
					{Address: "10.0.0.5", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.5/32"))
	})

	It("falls back to ExternalIP when no InternalIP is available", func() {
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				Addresses: []internalapi.NodeAddress{
					{Address: "192.0.2.7", Type: internalapi.ExternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("192.0.2.7/32"))
	})

	It("falls back to InternalIP when BGP is set but supplies no IPv4", func() {
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				BGP: &internalapi.NodeBGPSpec{IPv6Address: "fd00::1/64"},
				Addresses: []internalapi.NodeAddress{
					{Address: "10.0.0.5/24", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.5/24"))
		Expect(recorder.updates[0].ip6Addr).To(Equal("fd00::1/64"))
	})

	It("does not consult IPv6 addresses when BGP supplies an IPv6 (avoids overriding)", func() {
		// IPv6 fallback only applies when BGP is absent. With BGP set the
		// configured IPv6Address remains authoritative even if Addresses also
		// contains IPv6 entries.
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				BGP: &internalapi.NodeBGPSpec{IPv6Address: "fd00::1/64"},
				Addresses: []internalapi.NodeAddress{
					{Address: "fd00::99", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip6Addr).To(Equal("fd00::1/64"))
	})

	It("falls back to InternalIP for both families when BGP is nil and ipv6Support is on", func() {
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				Addresses: []internalapi.NodeAddress{
					{Address: "10.0.0.5", Type: internalapi.InternalIP},
					{Address: "fd00::99/64", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.5/32"))
		Expect(recorder.updates[0].ip6Addr).To(Equal("fd00::99/64"))
	})

	It("does not populate IPv6 from Addresses when ipv6Support is off", func() {
		passthru = NewDataplanePassthru(recorder, false)
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				Addresses: []internalapi.NodeAddress{
					{Address: "10.0.0.5", Type: internalapi.InternalIP},
					{Address: "fd00::99", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.5/32"))
		Expect(recorder.updates[0].ip6Addr).To(BeEmpty())
	})

	It("ignores Addresses without a recognised Type", func() {
		// Mirrors FindNodeAddress's behaviour: addresses with empty Type are
		// not used by the Internal/External fallback path.
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				Addresses: []internalapi.NodeAddress{
					{Address: "10.0.0.5"}, // no Type
				},
			},
		}))
		// No HostInfo can be derived → no callback for an IP, but the Node
		// still exists so we still emit an update (with empty addresses).
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].ip4Addr).To(BeEmpty())
		Expect(recorder.updates[0].ip6Addr).To(BeEmpty())
	})

	It("treats an empty BGP spec as a delete and only emits a remove if there was prior state", func() {
		// First create state with a real Node so we have something to remove.
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				BGP: &internalapi.NodeBGPSpec{IPv4Address: "10.0.0.1/24"},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.removes).To(BeEmpty())

		// Now an explicitly-empty BGP spec, no addresses → treated as a delete.
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec:       internalapi.NodeSpec{BGP: &internalapi.NodeBGPSpec{}},
		}))
		Expect(recorder.removes).To(Equal([]string{host}))
	})

	It("propagates BGP ASN even when no IP is supplied (using fallback for IPv4)", func() {
		asn, err := numorstring.ASNumberFromString("65000")
		Expect(err).NotTo(HaveOccurred())
		passthru.OnUpdate(nodeUpdate(host, &internalapi.Node{
			ObjectMeta: metav1.ObjectMeta{Name: host},
			Spec: internalapi.NodeSpec{
				BGP: &internalapi.NodeBGPSpec{ASNumber: &asn},
				Addresses: []internalapi.NodeAddress{
					{Address: "10.0.0.5", Type: internalapi.InternalIP},
				},
			},
		}))
		Expect(recorder.updates).To(HaveLen(1))
		Expect(recorder.updates[0].asnumber).To(Equal("65000"))
		Expect(recorder.updates[0].ip4Addr).To(Equal("10.0.0.5/32"))
	})
})
