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

package calc_test

import (
	. "github.com/projectcalico/felix/calc"

	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var testIP = mustParseIP("10.0.0.1")
var testIP2 = mustParseIP("10.0.0.2")
var testIPAs6 = net.IP{testIP.To16()}
var testIPAs4 = net.IP{testIP.To4()}

var _ = DescribeTable("Calculation graph pass-through tests",
	func(key model.Key, input interface{}, expUpdate interface{}, expRemove interface{}) {
		// Create a calculation graph/event buffer combo.
		eb := NewEventSequencer(nil)
		var messageReceived interface{}
		eb.Callback = func(message interface{}) {
			logrus.WithField("message", message).Info("Received message")
			messageReceived = message
		}
		cg := NewCalculationGraph(eb, "hostname")

		// Send in the update and flush the buffer.  It should deposit the message
		// via our callback.
		By("Emitting correct update")
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: input,
			},
		})
		eb.Flush()
		Expect(reflect.ValueOf(messageReceived).Elem().Interface()).To(Equal(expUpdate))

		// Send in the delete and flush the buffer.  It should deposit the message
		// via our callback.
		By("Emitting correct remove")
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVDeleted,
			KVPair: model.KVPair{
				Key:   key,
				Value: nil,
			},
		})
		eb.Flush()
		Expect(reflect.ValueOf(messageReceived).Elem().Interface()).To(Equal(expRemove))
	},
	Entry("IPPool",
		model.IPPoolKey{CIDR: mustParseNet("10.0.0.0/16")},
		&model.IPPool{
			CIDR: mustParseNet("10.0.0.0/16"),
		},
		proto.IPAMPoolUpdate{
			Id: "10.0.0.0-16",
			Pool: &proto.IPAMPool{
				Cidr:       "10.0.0.0/16",
				Masquerade: false,
			},
		},
		proto.IPAMPoolRemove{
			Id: "10.0.0.0-16",
		}),
	Entry("IPPool masquerade",
		model.IPPoolKey{CIDR: mustParseNet("10.0.0.0/16")},
		&model.IPPool{
			CIDR:       mustParseNet("10.0.0.0/16"),
			Masquerade: true,
		},
		proto.IPAMPoolUpdate{
			Id: "10.0.0.0-16",
			Pool: &proto.IPAMPool{
				Cidr:       "10.0.0.0/16",
				Masquerade: true,
			},
		},
		proto.IPAMPoolRemove{
			Id: "10.0.0.0-16",
		}),
	Entry("HostIP",
		model.HostIPKey{Hostname: "foo"},
		&testIP,
		proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		},
		proto.HostMetadataRemove{
			Hostname: "foo",
		}),
)

var _ = Describe("Host IP duplicate squashing test", func() {
	var eb *EventSequencer
	var messagesReceived []interface{}
	var cg *dispatcher.Dispatcher

	BeforeEach(func() {
		// Create a calculation graph/event buffer combo.
		eb = NewEventSequencer(nil)
		messagesReceived = nil
		eb.Callback = func(message interface{}) {
			logrus.WithField("message", message).Info("Received message")
			messagesReceived = append(messagesReceived, message)
		}
		cg = NewCalculationGraph(eb, "hostname")
	})

	It("should coalesce duplicate updates", func() {
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   model.HostIPKey{Hostname: "foo"},
				Value: &testIPAs6,
			},
		})
		eb.Flush()
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   model.HostIPKey{Hostname: "foo"},
				Value: &testIPAs4,
			},
		})
		eb.Flush()
		Expect(messagesReceived).To(ConsistOf(&proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		}))
	})
	It("should pass on genuine changes", func() {
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   model.HostIPKey{Hostname: "foo"},
				Value: &testIPAs6,
			},
		})
		eb.Flush()
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   model.HostIPKey{Hostname: "foo"},
				Value: &testIP2,
			},
		})
		eb.Flush()
		Expect(messagesReceived).To(ConsistOf(
			&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.1",
			},
			&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.2",
			},
		))
	})
	It("should pass on delete and recreate", func() {
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   model.HostIPKey{Hostname: "foo"},
				Value: &testIPAs6,
			},
		})
		eb.Flush()
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key: model.HostIPKey{Hostname: "foo"},
			},
		})
		eb.Flush()
		cg.OnUpdate(api.Update{
			UpdateType: api.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   model.HostIPKey{Hostname: "foo"},
				Value: &testIPAs6,
			},
		})
		eb.Flush()
		Expect(messagesReceived).To(ConsistOf(
			&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.1",
			},
			&proto.HostMetadataRemove{
				Hostname: "foo",
			},
			&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.1",
			},
		))
	})
})
