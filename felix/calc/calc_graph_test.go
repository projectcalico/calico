// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	googleproto "google.golang.org/protobuf/proto"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	extdataplane "github.com/projectcalico/calico/felix/dataplane/external"
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
var udpPort = proto.ServicePort{Port: 123, Protocol: "UDP"}
var tcpPort = proto.ServicePort{Port: 321, Protocol: "TCP"}

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
		lookupsCache := NewLookupsCache()
		cg := NewCalculationGraph(eb, lookupsCache, conf, func() {}).AllUpdDispatcher

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
		switch messageReceived.(type) {
		case *proto.IPAMPoolUpdate:
			Expect(googleproto.Equal(messageReceived.(*proto.IPAMPoolUpdate), expUpdate.(*proto.IPAMPoolUpdate))).To(BeTrue())
		case *proto.HostMetadataUpdate:
			Expect(googleproto.Equal(messageReceived.(*proto.HostMetadataUpdate), expUpdate.(*proto.HostMetadataUpdate))).To(BeTrue())
		case *proto.GlobalBGPConfigUpdate:
			Expect(googleproto.Equal(messageReceived.(*proto.GlobalBGPConfigUpdate), expUpdate.(*proto.GlobalBGPConfigUpdate))).To(BeTrue())
		case *proto.WireguardEndpointUpdate:
			Expect(googleproto.Equal(messageReceived.(*proto.WireguardEndpointUpdate), expUpdate.(*proto.WireguardEndpointUpdate))).To(BeTrue())
		case *proto.ServiceUpdate:
			Expect(googleproto.Equal(messageReceived.(*proto.ServiceUpdate), expUpdate.(*proto.ServiceUpdate))).To(BeTrue())
		}
		_, err := extdataplane.WrapPayloadWithEnvelope(messageReceived, 0)
		Expect(err).To(BeNil())

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
		switch messageReceived.(type) {
		case *proto.IPAMPoolRemove:
			Expect(googleproto.Equal(messageReceived.(*proto.IPAMPoolRemove), expRemove.(*proto.IPAMPoolRemove))).To(BeTrue())
		case *proto.HostMetadataRemove:
			Expect(googleproto.Equal(messageReceived.(*proto.HostMetadataRemove), expRemove.(*proto.HostMetadataRemove))).To(BeTrue())
		case *proto.GlobalBGPConfigUpdate:
			Expect(googleproto.Equal(messageReceived.(*proto.GlobalBGPConfigUpdate), expRemove.(*proto.GlobalBGPConfigUpdate))).To(BeTrue())
		case *proto.WireguardEndpointRemove:
			Expect(googleproto.Equal(messageReceived.(*proto.WireguardEndpointRemove), expRemove.(*proto.WireguardEndpointRemove))).To(BeTrue())
		case *proto.ServiceRemove:
			Expect(googleproto.Equal(messageReceived.(*proto.ServiceRemove), expRemove.(*proto.ServiceRemove))).To(BeTrue())
		}
		_, err = extdataplane.WrapPayloadWithEnvelope(messageReceived, 0)
		Expect(err).To(BeNil())
	},
	Entry("IPPool",
		model.IPPoolKey{CIDR: mustParseNet("10.0.0.0/16")},
		&model.IPPool{
			CIDR: mustParseNet("10.0.0.0/16"),
		},
		&proto.IPAMPoolUpdate{
			Id: "10.0.0.0-16",
			Pool: &proto.IPAMPool{
				Cidr:       "10.0.0.0/16",
				Masquerade: false,
			},
		},
		&proto.IPAMPoolRemove{
			Id: "10.0.0.0-16",
		}),
	Entry("IPPool masquerade",
		model.IPPoolKey{CIDR: mustParseNet("10.0.0.0/16")},
		&model.IPPool{
			CIDR:       mustParseNet("10.0.0.0/16"),
			Masquerade: true,
		},
		&proto.IPAMPoolUpdate{
			Id: "10.0.0.0-16",
			Pool: &proto.IPAMPool{
				Cidr:       "10.0.0.0/16",
				Masquerade: true,
			},
		},
		&proto.IPAMPoolRemove{
			Id: "10.0.0.0-16",
		}),
	Entry("HostIP",
		model.HostIPKey{Hostname: "foo"},
		&testIP,
		&proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		},
		&proto.HostMetadataRemove{
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
		&proto.GlobalBGPConfigUpdate{
			ServiceClusterCidrs:      []string{"1.2.0.0/16", "fd5f::/120"},
			ServiceExternalCidrs:     []string{"255.200.0.0/24"},
			ServiceLoadbalancerCidrs: []string{"255.220.0.0/24"},
		},
		&proto.GlobalBGPConfigUpdate{}),
	Entry("Wireguard",
		model.WireguardKey{NodeName: "localhost"},
		&model.Wireguard{InterfaceIPv4Addr: &testIP, PublicKey: "azerty"},
		&proto.WireguardEndpointUpdate{
			Hostname:          "localhost",
			PublicKey:         "azerty",
			InterfaceIpv4Addr: "10.0.0.1",
		},
		&proto.WireguardEndpointRemove{Hostname: "localhost"}),
	Entry("Services",
		model.ResourceKey{Kind: model.KindKubernetesService, Name: "svcname", Namespace: "default"},
		&kapiv1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svcname",
				Namespace: "default",
			},
			Spec: kapiv1.ServiceSpec{
				Type:           "ClusterIP",
				ClusterIPs:     []string{"10.96.0.1"},
				LoadBalancerIP: "1.1.1.1",
				ExternalIPs:    []string{"1.2.3.4"},
				Ports: []kapiv1.ServicePort{
					{
						Protocol: kapiv1.ProtocolUDP,
						Port:     123,
					},
					{
						Port: 321,
					},
				},
			},
		},
		&proto.ServiceUpdate{
			Name:           "svcname",
			Namespace:      "default",
			Type:           "ClusterIP",
			ClusterIps:     []string{"10.96.0.1"},
			LoadbalancerIp: "1.1.1.1",
			ExternalIps:    []string{"1.2.3.4"},
			Ports:          []*proto.ServicePort{&udpPort, &tcpPort},
		},
		&proto.ServiceRemove{
			Name:      "svcname",
			Namespace: "default",
		},
	),
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
		lookupsCache := NewLookupsCache()
		conf.FelixHostname = "hostname"
		cg = NewCalculationGraph(eb, lookupsCache, conf, func() {}).AllUpdDispatcher
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
		Expect(messagesReceived).To(HaveLen(1))
		Expect(googleproto.Equal(messagesReceived[0].(*proto.HostMetadataUpdate), &proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		})).To(BeTrue())
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
		Expect(messagesReceived).To(HaveLen(2))
		Expect(googleproto.Equal(messagesReceived[0].(*proto.HostMetadataUpdate), &proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		})).To(BeTrue())
		Expect(googleproto.Equal(messagesReceived[1].(*proto.HostMetadataUpdate), &proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.2",
		})).To(BeTrue())
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
		Expect(messagesReceived).To(HaveLen(3))
		Expect(googleproto.Equal(messagesReceived[0].(*proto.HostMetadataUpdate), &proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		})).To(BeTrue())
		Expect(googleproto.Equal(messagesReceived[1].(*proto.HostMetadataRemove), &proto.HostMetadataRemove{
			Hostname: "foo",
		})).To(BeTrue())
		Expect(googleproto.Equal(messagesReceived[2].(*proto.HostMetadataUpdate), &proto.HostMetadataUpdate{
			Hostname: "foo",
			Ipv4Addr: "10.0.0.1",
		})).To(BeTrue())
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
		lookupsCache := NewLookupsCache()
		calcGraph = NewCalculationGraph(eventBuf, lookupsCache, conf, func() {})
		statsCollector := NewStatsCollector(func(stats StatsUpdate) error {
			log.WithField("stats", stats).Info("Stats update")
			return nil
		})
		statsCollector.RegisterWith(calcGraph)
		validationFilter = NewValidationFilter(calcGraph.AllUpdDispatcher, conf)
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
