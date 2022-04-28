// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	. "github.com/projectcalico/calico/felix/calc"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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

	sendHostUpdate := func(name string, value interface{}) {
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.HostConfigKey{Name: name, Hostname: "myhost"},
				Value: value,
			},
		})
	}
	sendGlobalUpdate := func(name string, value interface{}) {
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.GlobalConfigKey{Name: name},
				Value: value,
			},
		})
	}
	sendReady := func(ready interface{}) {
		cb.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ReadyFlagKey{},
				Value: ready,
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
						host: map[string]string{},
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
							host:   map[string]string{},
							global: map[string]string{},
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
				host:   map[string]string{},
				global: map[string]string{},
			}))
		})
	})
})

type configUpdate struct {
	host   map[string]string
	global map[string]string
}

type configRecorder struct {
	Updates  []configUpdate
	NotReady bool
}

func (cr *configRecorder) OnConfigUpdate(globalConfig, hostConfig map[string]string) {
	cr.Updates = append(cr.Updates, configUpdate{
		host:   hostConfig,
		global: globalConfig,
	})
}

func (cr *configRecorder) OnDatastoreNotReady() {
	cr.NotReady = true
}

func (cr *configRecorder) Reset() {
	cr.Updates = nil
}
