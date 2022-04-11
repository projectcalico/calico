// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = DescribeTable("ModelWorkloadEndpointToProto",
	func(in model.WorkloadEndpoint, expected proto.WorkloadEndpoint) {
		out := calc.ModelWorkloadEndpointToProto(&in, []*proto.TierInfo{})
		Expect(*out).To(Equal(expected))
	},
	Entry("workload endpoint with NAT", model.WorkloadEndpoint{
		State:      "up",
		Name:       "bill",
		Mac:        mustParseMac("01:02:03:04:05:06"),
		ProfileIDs: []string{},
		IPv4Nets:   []net.IPNet{mustParseNet("10.28.0.13/32")},
		IPv6Nets:   []net.IPNet{},
		IPv4NAT: []model.IPNAT{
			{
				IntIP: mustParseIP("10.28.0.13"),
				ExtIP: mustParseIP("172.16.1.3"),
			},
		},
		IPv6NAT: []model.IPNAT{},
	}, proto.WorkloadEndpoint{
		State:      "up",
		Name:       "bill",
		Mac:        "01:02:03:04:05:06",
		ProfileIds: []string{},
		Ipv4Nets:   []string{"10.28.0.13/32"},
		Ipv6Nets:   []string{},
		Tiers:      []*proto.TierInfo{},
		Ipv4Nat: []*proto.NatInfo{
			{
				ExtIp: "172.16.1.3",
				IntIp: "10.28.0.13",
			},
		},
		Ipv6Nat:                    []*proto.NatInfo{},
		AllowSpoofedSourcePrefixes: []string{},
	}),
	Entry("workload endpoint with source IP spoofing configured", model.WorkloadEndpoint{
		State:                      "up",
		Name:                       "bill",
		AllowSpoofedSourcePrefixes: []net.IPNet{net.MustParseCIDR("8.8.8.8/32")},
	}, proto.WorkloadEndpoint{
		State:                      "up",
		Name:                       "bill",
		Ipv4Nets:                   []string{},
		Ipv6Nets:                   []string{},
		Tiers:                      []*proto.TierInfo{},
		Ipv4Nat:                    []*proto.NatInfo{},
		Ipv6Nat:                    []*proto.NatInfo{},
		AllowSpoofedSourcePrefixes: []string{"8.8.8.8/32"},
	}),
)

var _ = Describe("ParsedRulesToActivePolicyUpdate", func() {
	var (
		fullyLoadedParsedRules = calc.ParsedRules{
			Namespace: "namespace",
			OutboundRules: []*calc.ParsedRule{
				{Action: "Allow"},
			},
			InboundRules: []*calc.ParsedRule{
				{Action: "Deny"},
			},
			PreDNAT:   true,
			Untracked: true,
		}
		fullyLoadedProtoRules = proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{
				Tier: "default",
				Name: "a-policy",
			},
			Policy: &proto.Policy{
				Namespace:     "namespace",
				InboundRules:  []*proto.Rule{{Action: "Deny"}},
				OutboundRules: []*proto.Rule{{Action: "Allow"}},
				Untracked:     true,
				PreDnat:       true,
			},
		}
	)

	It("a fully-loaded ParsedRules struct should result in all fields being set in the protobuf rules", func() {
		// We use reflection to scan all the fields in the protobuf rule to make sure that they're
		// all filled in.  If any are still at their zero value, either hte test is out of date
		// or we forgot to add conversion logic for that field.
		protoUpdate := calc.ParsedRulesToActivePolicyUpdate(model.PolicyKey{Name: "a-policy"}, &fullyLoadedParsedRules)
		protoPolicy := *protoUpdate.Policy
		protoPolicyValue := reflect.ValueOf(protoPolicy)
		numFields := protoPolicyValue.NumField()
		for i := 0; i < numFields; i++ {
			field := protoPolicyValue.Field(i)
			fieldName := reflect.TypeOf(protoPolicy).Field(i).Name
			Expect(field.Interface()).NotTo(Equal(reflect.Zero(field.Type()).Interface()),
				fmt.Sprintf("Field %s in the protobuf struct was still at its zero value; "+
					"missing from conversion or fully-loaded rule?", fieldName))
		}
	})

	It("should convert the fully-loaded rule", func() {
		protoUpdate := calc.ParsedRulesToActivePolicyUpdate(model.PolicyKey{Name: "a-policy"}, &fullyLoadedParsedRules)
		// Check the rule IDs are filled in but ignore them for comparisons.
		for _, r := range protoUpdate.Policy.InboundRules {
			Expect(r.RuleId).ToNot(Equal(""))
			r.RuleId = ""
		}
		for _, r := range protoUpdate.Policy.OutboundRules {
			Expect(r.RuleId).ToNot(Equal(""))
			r.RuleId = ""
		}
		Expect(protoUpdate).To(Equal(&fullyLoadedProtoRules))
	})
})

var _ = DescribeTable("ModelHostEndpointToProto",
	func(in model.HostEndpoint, tiers, untrackedTiers []*proto.TierInfo, forwardTiers []*proto.TierInfo, expected proto.HostEndpoint) {
		out := calc.ModelHostEndpointToProto(&in, tiers, untrackedTiers, nil, forwardTiers)
		Expect(*out).To(Equal(expected))
	},
	Entry("minimal endpoint",
		model.HostEndpoint{
			ExpectedIPv4Addrs: []net.IP{mustParseIP("10.28.0.13")},
		},
		nil,
		nil,
		nil,
		proto.HostEndpoint{
			ExpectedIpv4Addrs: []string{"10.28.0.13"},
			ExpectedIpv6Addrs: []string{},
		},
	),
	Entry("fully loaded endpoint",
		model.HostEndpoint{
			Name:              "eth0",
			ExpectedIPv4Addrs: []net.IP{mustParseIP("10.28.0.13"), mustParseIP("10.28.0.14")},
			ExpectedIPv6Addrs: []net.IP{mustParseIP("dead::beef"), mustParseIP("dead::bee5")},
			Labels: map[string]string{
				"a": "b",
			},
			ProfileIDs: []string{"prof1"},
		},
		[]*proto.TierInfo{{Name: "a", IngressPolicies: []string{"b", "c"}}},
		[]*proto.TierInfo{{Name: "d", IngressPolicies: []string{"e", "f"}}},
		[]*proto.TierInfo{{Name: "g", IngressPolicies: []string{"h", "i"}}},
		proto.HostEndpoint{
			Name:              "eth0",
			ExpectedIpv4Addrs: []string{"10.28.0.13", "10.28.0.14"},
			ExpectedIpv6Addrs: []string{"dead::beef", "dead::bee5"},
			Tiers:             []*proto.TierInfo{{Name: "a", IngressPolicies: []string{"b", "c"}}},
			UntrackedTiers:    []*proto.TierInfo{{Name: "d", IngressPolicies: []string{"e", "f"}}},
			ForwardTiers:      []*proto.TierInfo{{Name: "g", IngressPolicies: []string{"h", "i"}}},
			ProfileIds:        []string{"prof1"},
		},
	),
	Entry("fully loaded endpoint with policies in same tier",
		model.HostEndpoint{
			Name:              "eth0",
			ExpectedIPv4Addrs: []net.IP{mustParseIP("10.28.0.13"), mustParseIP("10.28.0.14")},
			ExpectedIPv6Addrs: []net.IP{mustParseIP("dead::beef"), mustParseIP("dead::bee5")},
			Labels: map[string]string{
				"a": "b",
			},
			ProfileIDs: []string{"prof1"},
		},
		[]*proto.TierInfo{{Name: "a", IngressPolicies: []string{"b"}}},
		[]*proto.TierInfo{{Name: "a", EgressPolicies: []string{"c"}}},
		[]*proto.TierInfo{{Name: "a", EgressPolicies: []string{"d"}}},
		proto.HostEndpoint{
			Name:              "eth0",
			ExpectedIpv4Addrs: []string{"10.28.0.13", "10.28.0.14"},
			ExpectedIpv6Addrs: []string{"dead::beef", "dead::bee5"},
			Tiers:             []*proto.TierInfo{{Name: "a", IngressPolicies: []string{"b"}}},
			UntrackedTiers:    []*proto.TierInfo{{Name: "a", EgressPolicies: []string{"c"}}},
			ForwardTiers:      []*proto.TierInfo{{Name: "a", EgressPolicies: []string{"d"}}},
			ProfileIds:        []string{"prof1"},
		},
	),
)

var _ = Describe("ServiceAccount update/remove", func() {
	var uut *calc.EventSequencer
	var recorder *dataplaneRecorder

	BeforeEach(func() {
		uut = calc.NewEventSequencer(&dummyConfigInterface{})
		recorder = &dataplaneRecorder{}
		uut.Callback = recorder.record
	})

	It("should flush latest update", func() {
		uut.OnServiceAccountUpdate(&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.OnServiceAccountUpdate(&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v2"},
		})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{
			&proto.ServiceAccountUpdate{
				Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
				Labels: map[string]string{"k1": "v2"},
			}}))
	})

	It("should coalesce add + remove", func() {
		uut.OnServiceAccountUpdate(&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.OnServiceAccountRemove(proto.ServiceAccountID{Name: "test", Namespace: "test"})
		uut.Flush()
		Expect(recorder.Messages).To(BeNil())
	})

	It("should coalesce remove + add", func() {
		uut.OnServiceAccountRemove(proto.ServiceAccountID{Name: "test", Namespace: "test"})
		uut.OnServiceAccountUpdate(&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v1"},
		}}))
	})

	It("should send remove for flushed accounts", func() {
		uut.OnServiceAccountUpdate(&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{&proto.ServiceAccountUpdate{
			Id:     &proto.ServiceAccountID{Name: "test", Namespace: "test"},
			Labels: map[string]string{"k1": "v1"},
		}}))
		// Clear messages
		recorder.Messages = make([]interface{}, 0)

		uut.OnServiceAccountRemove(proto.ServiceAccountID{Name: "test", Namespace: "test"})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{&proto.ServiceAccountRemove{
			Id: &proto.ServiceAccountID{Name: "test", Namespace: "test"},
		}}))
	})
})

var _ = Describe("Namespace update/remove", func() {
	var uut *calc.EventSequencer
	var recorder *dataplaneRecorder

	BeforeEach(func() {
		uut = calc.NewEventSequencer(&dummyConfigInterface{})
		recorder = &dataplaneRecorder{}
		uut.Callback = recorder.record
	})

	It("should flush latest update", func() {
		uut.OnNamespaceUpdate(&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.OnNamespaceUpdate(&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v2"},
		})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{
			&proto.NamespaceUpdate{
				Id:     &proto.NamespaceID{Name: "test"},
				Labels: map[string]string{"k1": "v2"},
			}}))
	})

	It("should coalesce add + remove", func() {
		uut.OnNamespaceUpdate(&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.OnNamespaceRemove(proto.NamespaceID{Name: "test"})
		uut.Flush()
		Expect(recorder.Messages).To(BeNil())
	})

	It("should coalesce remove + add", func() {
		uut.OnNamespaceRemove(proto.NamespaceID{Name: "test"})
		uut.OnNamespaceUpdate(&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v1"},
		}}))
	})

	It("should send remove for flushed accounts", func() {
		uut.OnNamespaceUpdate(&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v1"},
		})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{&proto.NamespaceUpdate{
			Id:     &proto.NamespaceID{Name: "test"},
			Labels: map[string]string{"k1": "v1"},
		}}))
		// Clear messages
		recorder.Messages = make([]interface{}, 0)

		uut.OnNamespaceRemove(proto.NamespaceID{Name: "test"})
		uut.Flush()
		Expect(recorder.Messages).To(Equal([]interface{}{&proto.NamespaceRemove{
			Id: &proto.NamespaceID{Name: "test"},
		}}))
	})
})

var _ = Describe("IPPool update/remove", func() {
	var uut *calc.EventSequencer
	var recorder *dataplaneRecorder

	BeforeEach(func() {
		uut = calc.NewEventSequencer(&dummyConfigInterface{})
		recorder = &dataplaneRecorder{}
		uut.Callback = recorder.record
	})

	It("Create an IP Pool and delete it without flushing the event sequencer", func() {
		uut.OnIPPoolUpdate(model.IPPoolKey{CIDR: mustParseNet("10.0.0.0/16")},
			&model.IPPool{
				CIDR: mustParseNet("10.0.0.0/16"),
			})
		uut.OnIPPoolRemove(model.IPPoolKey{CIDR: mustParseNet("10.0.0.0/16")})
		Expect(recorder.Messages).To(BeNil())
	})
})

type dataplaneRecorder struct {
	Messages []interface{}
}

func (d *dataplaneRecorder) record(message interface{}) {
	d.Messages = append(d.Messages, message)
}

type dummyConfigInterface struct{}

func (i *dummyConfigInterface) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return false, nil
}

func (i *dummyConfigInterface) RawValues() map[string]string {
	return nil
}
