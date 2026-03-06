// Copyright (c) 2017,2025 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("ConfigBatcher", func() {
	var cb *ConfigBatcher
	var recorder *configRecorder

	BeforeEach(func() {
		recorder = &configRecorder{}
		cb = NewConfigBatcher("myhost", recorder)
	})

	sendHostUpdate := func(name string, value any) {
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.HostConfigKey{Name: name, Hostname: "myhost"},
				Value: value,
			},
		})
	}
	sendGlobalUpdate := func(name string, value any) {
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.GlobalConfigKey{Name: name},
				Value: value,
			},
		})
	}
	sendReady := func(ready any) {
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ReadyFlagKey{},
				Value: ready,
			},
		})
	}
	sendFelixConfigResource := func(name string, fc *apiv3.FelixConfiguration) {
		var value any
		if fc != nil {
			value = fc
		}
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{
					Kind: apiv3.KindFelixConfiguration,
					Name: name,
				},
				Value: value,
			},
		})
	}
	sendNodeResource := func(name string, node *internalapi.Node) {
		var value any
		if node != nil {
			value = node
		}
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{
					Kind: internalapi.KindNode,
					Name: name,
				},
				Value: value,
			},
		})
	}

	Context("after sending some updates", func() {
		BeforeEach(func() {
			sendHostUpdate("foo", "bar")
			sendGlobalUpdate("biff", "bop")
			sendReady(true)
		})
		It("shouldn't emit anything yet", func() {
			Expect(recorder.Updates).To(BeEmpty())
			Expect(recorder.NotReady).To(BeFalse())
		})

		Context("after sending the in-sync", func() {
			BeforeEach(func() {
				cb.OnDatamodelStatus(api.InSync)
			})
			It("should emit one event", func() {
				Expect(recorder.Updates).To(ConsistOf(configUpdate{
					host: map[string]string{
						"foo": "bar",
					},
					selector: map[string]string{},
					global: map[string]string{
						"biff": "bop",
					},
				}))
				Expect(recorder.NotReady).To(BeFalse())
			})

			Context("after sending in more config", func() {
				BeforeEach(func() {
					recorder.Reset()
					sendHostUpdate("foo", "biz")
				})
				It("should emit one event", func() {
					Expect(recorder.Updates).To(ConsistOf(configUpdate{
						host: map[string]string{
							"foo": "biz",
						},
						selector: map[string]string{},
						global: map[string]string{
							"biff": "bop",
						},
					}))
					Expect(recorder.NotReady).To(BeFalse())
				})
			})

			Context("after deleting a key", func() {
				BeforeEach(func() {
					recorder.Reset()
					sendHostUpdate("foo", nil)
				})
				It("should emit one event", func() {
					Expect(recorder.Updates).To(ConsistOf(configUpdate{
						host:     map[string]string{},
						selector: map[string]string{},
						global: map[string]string{
							"biff": "bop",
						},
					}))
					Expect(recorder.NotReady).To(BeFalse())
				})
				Context("after deleting a global key", func() {
					BeforeEach(func() {
						recorder.Reset()
						sendGlobalUpdate("biff", nil)
					})
					It("should emit one event", func() {
						Expect(recorder.Updates).To(ConsistOf(configUpdate{
							host:     map[string]string{},
							selector: map[string]string{},
							global:   map[string]string{},
						}))
						Expect(recorder.NotReady).To(BeFalse())
					})
				})
			})

			Context("after sending in no-op updates", func() {
				BeforeEach(func() {
					recorder.Reset()
					sendHostUpdate("foo", "bar")
					sendGlobalUpdate("biff", "bop")
					sendReady(true)
					sendHostUpdate("fooble", nil)
					sendGlobalUpdate("biffle", nil)
				})
				It("should swallow the events", func() {
					Expect(recorder.Updates).To(BeEmpty())
					Expect(recorder.NotReady).To(BeFalse())
				})
			})

			Context("after deleting ready flag", func() {
				BeforeEach(func() {
					recorder.Reset()
					sendReady(nil)
				})
				It("should emit a not ready", func() {
					Expect(recorder.NotReady).To(BeTrue())
				})
			})

			Context("after setting ready flag to false", func() {
				BeforeEach(func() {
					recorder.Reset()
					sendReady(false)
				})
				It("should emit a not ready", func() {
					Expect(recorder.NotReady).To(BeTrue())
				})
			})
		})
	})

	Context("after sending in-sync with no config", func() {
		BeforeEach(func() {
			cb.OnDatamodelStatus(api.InSync)
		})
		It("should emit a not-ready and empty config", func() {
			Expect(recorder.NotReady).To(BeTrue())
			Expect(recorder.Updates).To(ConsistOf(configUpdate{
				host:     map[string]string{},
				selector: map[string]string{},
				global:   map[string]string{},
			}))
		})
	})

	Context("selector-scoped FelixConfiguration", func() {
		BeforeEach(func() {
			sendReady(true)
			// Set up node labels for myhost.
			sendNodeResource("myhost", &internalapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "myhost",
					Labels: map[string]string{
						"role": "gpu",
						"zone": "us-east-1a",
					},
				},
			})
		})

		Context("with a matching selector-scoped FelixConfiguration", func() {
			BeforeEach(func() {
				fc := apiv3.NewFelixConfiguration()
				fc.Name = "gpu-nodes"
				enabled := true
				fc.Spec.NodeSelector = "role == 'gpu'"
				fc.Spec.BPFEnabled = &enabled
				sendFelixConfigResource("gpu-nodes", fc)
				cb.OnDatamodelStatus(api.InSync)
			})
			It("should include the matching selector config", func() {
				Expect(recorder.Updates).To(HaveLen(1))
				Expect(recorder.Updates[0].selector).To(HaveKeyWithValue("BPFEnabled", "true"))
			})
		})

		Context("with a non-matching selector-scoped FelixConfiguration", func() {
			BeforeEach(func() {
				fc := apiv3.NewFelixConfiguration()
				fc.Name = "storage-nodes"
				enabled := true
				fc.Spec.NodeSelector = "role == 'storage'"
				fc.Spec.BPFEnabled = &enabled
				sendFelixConfigResource("storage-nodes", fc)
				cb.OnDatamodelStatus(api.InSync)
			})
			It("should not include the non-matching selector config", func() {
				Expect(recorder.Updates).To(HaveLen(1))
				Expect(recorder.Updates[0].selector).To(BeEmpty())
			})
		})

		Context("with label change causing config re-evaluation", func() {
			BeforeEach(func() {
				fc := apiv3.NewFelixConfiguration()
				fc.Name = "gpu-nodes"
				enabled := true
				fc.Spec.NodeSelector = "role == 'gpu'"
				fc.Spec.BPFEnabled = &enabled
				sendFelixConfigResource("gpu-nodes", fc)
				cb.OnDatamodelStatus(api.InSync)

				// Now change the labels so it no longer matches.
				recorder.Reset()
				sendNodeResource("myhost", &internalapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "myhost",
						Labels: map[string]string{
							"role": "standard",
							"zone": "us-east-1a",
						},
					},
				})
			})
			It("should no longer include the config after label change", func() {
				Expect(recorder.Updates).To(HaveLen(1))
				Expect(recorder.Updates[0].selector).To(BeEmpty())
			})
		})

		Context("deleting a selector-scoped FelixConfiguration", func() {
			BeforeEach(func() {
				fc := apiv3.NewFelixConfiguration()
				fc.Name = "gpu-nodes"
				enabled := true
				fc.Spec.NodeSelector = "role == 'gpu'"
				fc.Spec.BPFEnabled = &enabled
				sendFelixConfigResource("gpu-nodes", fc)
				cb.OnDatamodelStatus(api.InSync)

				recorder.Reset()
				sendFelixConfigResource("gpu-nodes", nil)
			})
			It("should remove the selector config", func() {
				Expect(recorder.Updates).To(HaveLen(1))
				Expect(recorder.Updates[0].selector).To(BeEmpty())
			})
		})

		Context("ignoring node updates for other hosts", func() {
			BeforeEach(func() {
				fc := apiv3.NewFelixConfiguration()
				fc.Name = "gpu-nodes"
				enabled := true
				fc.Spec.NodeSelector = "role == 'gpu'"
				fc.Spec.BPFEnabled = &enabled
				sendFelixConfigResource("gpu-nodes", fc)
				cb.OnDatamodelStatus(api.InSync)

				recorder.Reset()
				sendNodeResource("otherhost", &internalapi.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "otherhost",
						Labels: map[string]string{
							"role": "storage",
						},
					},
				})
			})
			It("should not trigger a config update", func() {
				Expect(recorder.Updates).To(BeEmpty())
			})
		})
	})
})

type configUpdate struct {
	host     map[string]string
	selector map[string]string
	global   map[string]string
}

type configRecorder struct {
	Updates  []configUpdate
	NotReady bool
}

func (cr *configRecorder) OnConfigUpdate(globalConfig, selectorConfig, hostConfig map[string]string) {
	cr.Updates = append(cr.Updates, configUpdate{
		host:     hostConfig,
		selector: selectorConfig,
		global:   globalConfig,
	})
}

func (cr *configRecorder) OnDatastoreNotReady() {
	cr.NotReady = true
}

func (cr *configRecorder) Reset() {
	cr.Updates = nil
}
