// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	. "github.com/projectcalico/felix/go/felix/calc"

	"github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"reflect"
)

var testIP = mustParseIP("10.0.0.1")

var _ = DescribeTable("Calculation graph pass-through tests",
	func(key model.Key, input interface{}, expUpdate interface{}, expRemove interface{}) {
		// Create a calculation graph/event buffer combo.
		eb := NewEventBuffer(nil)
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
