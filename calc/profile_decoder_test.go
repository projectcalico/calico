// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/calc"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("profileDecoder", func() {
	var uut *calc.ProfileDecoder
	var callbacks *passthruCallbackRecorder

	BeforeEach(func() {
		callbacks = &passthruCallbackRecorder{}
		uut = calc.NewProfileDecoder(callbacks)
	})

	Describe("RegisterWith", func() {
		var disp *dispatcher.Dispatcher

		BeforeEach(func() {
			disp = dispatcher.NewDispatcher()
			uut.RegisterWith(disp)
		})

		It("should Register for ProfileLabels only", func() {
			disp.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: model.HostEndpointKey{}},
				UpdateType: api.UpdateTypeKVNew,
			})
		})
	})

	Describe("OnUpdate", func() {

		It("should pass k8s service account update", func() {
			update := addUpdate(conversion.ServiceAccountProfileNamePrefix+"test_namespace.test_serviceaccount",
				map[string]string{
					conversion.ServiceAccountLabelPrefix + "k1": "v1",
					conversion.ServiceAccountLabelPrefix + "k2": "v2",
				})
			uut.OnUpdate(update)
			Expect(callbacks.saUpdates).To(Equal([]*proto.ServiceAccountUpdate{
				{
					Id: &proto.ServiceAccountID{
						Namespace: "test_namespace",
						Name:      "test_serviceaccount",
					},
					Labels: map[string]string{"k1": "v1", "k2": "v2"},
				},
			}))
		})

		It("should pass k8s namespace update", func() {
			update := addUpdate(conversion.NamespaceProfileNamePrefix+"test_namespace",
				map[string]string{
					conversion.NamespaceLabelPrefix + "k1": "v1",
					conversion.NamespaceLabelPrefix + "k2": "v2",
				})
			uut.OnUpdate(update)
			Expect(callbacks.nsUpdates).To(Equal([]*proto.NamespaceUpdate{
				{
					Id: &proto.NamespaceID{
						Name: "test_namespace",
					},
					Labels: map[string]string{"k1": "v1", "k2": "v2"},
				},
			}))
		})

		It("should not pass non-recognized updates", func() {
			update := addUpdate("test_profile", map[string]string{"k1": "v1", "k2": "v2"})
			uut.OnUpdate(update)
			Expect(callbacks.saUpdates).To(BeNil())
		})

		It("should send k8s service account profile remove", func() {
			update := removeUpdate(conversion.ServiceAccountProfileNamePrefix + "test_namespace.test_serviceaccount")
			uut.OnUpdate(update)
			Expect(callbacks.saRemoves).To(Equal([]proto.ServiceAccountID{
				{Name: "test_serviceaccount", Namespace: "test_namespace"},
			}))
		})

		It("should send k8s namespace remove", func() {
			update := removeUpdate(conversion.NamespaceProfileNamePrefix + "test_namespace")
			uut.OnUpdate(update)
			Expect(callbacks.nsRemoves).To(Equal([]proto.NamespaceID{
				{Name: "test_namespace"},
			}))
		})

		It("should not send non-recognized remove", func() {
			update := removeUpdate("test_profile")
			uut.OnUpdate(update)
			Expect(callbacks.saRemoves).To(BeNil())
		})

		It("should not send malformed k8s service account profile update", func() {
			update := addUpdate(conversion.ServiceAccountProfileNamePrefix+"test_namespace-test_serviceaccount",
				map[string]string{
					conversion.ServiceAccountLabelPrefix + "k1": "v1",
					conversion.ServiceAccountLabelPrefix + "k2": "v2",
				})
			uut.OnUpdate(update)
			Expect(callbacks.saUpdates).To(BeNil())
		})
	})
})

type passthruCallbackRecorder struct {
	saUpdates []*proto.ServiceAccountUpdate
	saRemoves []proto.ServiceAccountID
	nsUpdates []*proto.NamespaceUpdate
	nsRemoves []proto.NamespaceID
}

func (p *passthruCallbackRecorder) OnHostIPUpdate(hostname string, ip *net.IP) {
	Fail("HostIPUpdate received")
}

func (p *passthruCallbackRecorder) OnHostIPRemove(hostname string) {
	Fail("HostIPRemove received")
}

func (p *passthruCallbackRecorder) OnIPPoolUpdate(model.IPPoolKey, *model.IPPool) {
	Fail("IPPoolUpdate received")
}

func (p *passthruCallbackRecorder) OnIPPoolRemove(model.IPPoolKey) {
	Fail("IPPoolRemove received")
}

func (p *passthruCallbackRecorder) OnServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	p.saUpdates = append(p.saUpdates, update)
}

func (p *passthruCallbackRecorder) OnServiceAccountRemove(id proto.ServiceAccountID) {
	p.saRemoves = append(p.saRemoves, id)
}

func (p *passthruCallbackRecorder) OnNamespaceUpdate(update *proto.NamespaceUpdate) {
	p.nsUpdates = append(p.nsUpdates, update)
}

func (p *passthruCallbackRecorder) OnNamespaceRemove(id proto.NamespaceID) {
	p.nsRemoves = append(p.nsRemoves, id)
}

func labelsKV(name string, labels interface{}) model.KVPair {
	return model.KVPair{
		Key: model.ProfileLabelsKey{
			ProfileKey: model.ProfileKey{Name: name}},
		Value: labels,
	}
}

func addUpdate(name string, labels map[string]string) api.Update {
	return api.Update{
		KVPair:     labelsKV(name, labels),
		UpdateType: api.UpdateTypeKVNew,
	}
}

func removeUpdate(name string) api.Update {
	return api.Update{
		KVPair:     labelsKV(name, nil),
		UpdateType: api.UpdateTypeKVDeleted,
	}
}
