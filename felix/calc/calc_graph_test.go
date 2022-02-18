// Copyright (c) 2016-2018,2020-2021 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/felix/config"

	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var testIP = mustParseIP("10.0.0.1")
var testIP2 = mustParseIP("10.0.0.2")
var testIPAs6 = net.IP{IP: testIP.To16()}
var testIPAs4 = net.IP{IP: testIP.To4()}

var _ = DescribeTable("Calculation graph pass-through tests",
	func(key model.Key, input interface{}, expUpdate interface{}, expRemove interface{}) {
		// Create a calculation graph/event buffer combo.
		eb := NewEventSequencer(nil)
		var messageReceived interface{}
		eb.Callback = func(message interface{}) {
			log.WithField("message", message).Info("Received message")
			messageReceived = message
		}
		conf := config.New()
		conf.FelixHostname = "hostname"
		cg := NewCalculationGraph(eb, conf, func() {}).AllUpdDispatcher

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
	Entry("Global BGPConfiguration",
		model.ResourceKey{Kind: v3.KindBGPConfiguration, Name: "default"},
		&v3.BGPConfiguration{
			Spec: v3.BGPConfigurationSpec{
				ServiceClusterIPs: []v3.ServiceClusterIPBlock{
					{
						CIDR: "1.2.0.0/16",
					},
					{
						CIDR: "fd5f::/120",
					},
				},
				ServiceExternalIPs: []v3.ServiceExternalIPBlock{
					{
						CIDR: "255.200.0.0/24",
					},
				},
				ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{
					{
						CIDR: "255.220.0.0/24",
					},
				},
			},
		},
		proto.GlobalBGPConfigUpdate{
			ServiceClusterCidrs:      []string{"1.2.0.0/16", "fd5f::/120"},
			ServiceExternalCidrs:     []string{"255.200.0.0/24"},
			ServiceLoadbalancerCidrs: []string{"255.220.0.0/24"},
		},
		proto.GlobalBGPConfigUpdate{}),
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
			log.WithField("message", message).Info("Received message")
			messagesReceived = append(messagesReceived, message)
		}
		conf := config.New()
		conf.FelixHostname = "hostname"
		cg = NewCalculationGraph(eb, conf, func() {}).AllUpdDispatcher
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

var _ = Describe("specific scenario tests", func() {
	var validationFilter *ValidationFilter
	var calcGraph *CalcGraph
	var mockDataplane *mock.MockDataplane
	var eventBuf *EventSequencer

	BeforeEach(func() {
		mockDataplane = mock.NewMockDataplane()
		eventBuf = NewEventSequencer(mockDataplane)
		eventBuf.Callback = mockDataplane.OnEvent
		conf := config.New()
		conf.FelixHostname = localHostname
		calcGraph = NewCalculationGraph(eventBuf, conf, func() {})
		statsCollector := NewStatsCollector(func(stats StatsUpdate) error {
			log.WithField("stats", stats).Info("Stats update")
			return nil
		})
		statsCollector.RegisterWith(calcGraph)
		validationFilter = NewValidationFilter(calcGraph.AllUpdDispatcher)
	})

	It("should squash no-op policy updates", func() {
		// First set up a state with an endpoint and some policy.
		validationFilter.OnUpdates(localEp1WithPolicy.KVDeltas(empty))
		validationFilter.OnStatusUpdated(api.InSync)
		eventBuf.Flush()

		numEventsBeforeSendingDupe := mockDataplane.NumEventsRecorded()
		validationFilter.OnUpdates([]api.Update{{
			KVPair:     pol1KVPair,
			UpdateType: api.UpdateTypeKVUpdated,
		}})
		eventBuf.Flush()

		Expect(mockDataplane.NumEventsRecorded()).To(Equal(numEventsBeforeSendingDupe))
	})
})
