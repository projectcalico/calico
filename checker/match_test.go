// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package checker

import (
	"testing"

	"github.com/envoyproxy/data-plane-api/envoy/api/v2/core"
	auth "github.com/envoyproxy/data-plane-api/envoy/service/auth/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/proto"
)

var (
	socketAddressProtocolTCP = &envoy_api_v2_core.Address{
		&envoy_api_v2_core.Address_SocketAddress{
			&envoy_api_v2_core.SocketAddress{
				Protocol: envoy_api_v2_core.SocketAddress_TCP,
			},
		},
	}

	socketAddressProtocolUDP = &envoy_api_v2_core.Address{
		&envoy_api_v2_core.Address_SocketAddress{
			&envoy_api_v2_core.SocketAddress{
				Protocol: envoy_api_v2_core.SocketAddress_UDP,
			},
		},
	}
)

// If no service account names are given, the clause matches any name.
func TestMatchName(t *testing.T) {
	testCases := []struct {
		title  string
		names  []string
		name   string
		result bool
	}{
		{"empty", []string{}, "reginald", true},
		{"match", []string{"susan", "jim", "reginald"}, "reginald", true},
		{"no match", []string{"susan", "jim", "reginald"}, "steven", false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			result := matchName(tc.names, tc.name)
			Expect(result).To(Equal(tc.result))
		})
	}
}

// An empty label selector matches any set of labels.
func TestMatchLabels(t *testing.T) {
	testCases := []struct {
		title    string
		selector string
		labels   map[string]string
		result   bool
	}{
		{"empty", "", map[string]string{"app": "foo", "env": "prod"}, true},
		{"bad selector", "not.a.real.selector", map[string]string{"app": "foo", "env": "prod"}, false},
		{"good selector", "app == 'foo'", map[string]string{"app": "foo", "env": "prod"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			result := matchLabels(tc.selector, tc.labels)
			Expect(result).To(Equal(tc.result))
		})
	}
}

// HTTP Methods clause with empty list will match any method.
func TestMatchHTTPMethods(t *testing.T) {
	testCases := []struct {
		title   string
		methods []string
		method  string
		result  bool
	}{
		{"empty", []string{}, "GET", true},
		{"match", []string{"GET", "HEAD"}, "GET", true},
		// HTTP methods are case sensitive. https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
		{"case sensitive", []string{"get", "HEAD"}, "GET", false},
		{"wildcard", []string{"*"}, "MADNESS", true},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(matchHTTPMethods(tc.methods, tc.method)).To(Equal(tc.result))
		})
	}
}

// An omitted HTTP Match clause always matches.
func TestMatchHTTPNil(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.AttributeContext_HttpRequest{}
	Expect(matchHTTP(nil, req)).To(BeTrue())
}

// Matching a whole rule should require matching all subclauses.
func TestMatchRule(t *testing.T) {
	RegisterTestingT(t)
	srcAddr := "192.168.4.22"
	dstAddr := "10.54.44.23"

	rule := &proto.Rule{
		SrcServiceAccountMatch: &proto.ServiceAccountMatch{
			Names: []string{"john", "stevie", "sam"},
		},
		DstServiceAccountMatch: &proto.ServiceAccountMatch{
			Names: []string{"ian"},
		},
		SrcIpSetIds:    []string{"src0", "src1"},
		NotSrcIpSetIds: []string{"notSrc0", "notSrc1"},
		DstIpSetIds:    []string{"dst0", "dst1"},
		NotDstIpSetIds: []string{"notDst0", "notDst1"},

		HttpMatch: &proto.HTTPMatch{
			Methods: []string{"GET", "POST"},
		},
		Protocol: &proto.Protocol{
			&proto.Protocol_Name{
				Name: "TCP",
			},
		},
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sam",
			Address: &envoy_api_v2_core.Address{Address: &envoy_api_v2_core.Address_SocketAddress{
				SocketAddress: &envoy_api_v2_core.SocketAddress{
					Address:       srcAddr,
					Protocol:      envoy_api_v2_core.SocketAddress_TCP,
					PortSpecifier: &envoy_api_v2_core.SocketAddress_PortValue{PortValue: 8458},
				}}},
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/ian",
			Address: &envoy_api_v2_core.Address{Address: &envoy_api_v2_core.Address_SocketAddress{
				SocketAddress: &envoy_api_v2_core.SocketAddress{
					Address:       dstAddr,
					Protocol:      envoy_api_v2_core.SocketAddress_TCP,
					PortSpecifier: &envoy_api_v2_core.SocketAddress_PortValue{PortValue: 80},
				}}},
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}

	store := policystore.NewPolicyStore()
	addIPSet(store, "src0", srcAddr)
	addIPSet(store, "src1", srcAddr, dstAddr)
	addIPSet(store, "notSrc0", "5.6.7.8", dstAddr)
	addIPSet(store, "notSrc1", "5.6.7.8")
	addIPSet(store, "dst0", dstAddr)
	addIPSet(store, "dst1", srcAddr, dstAddr)
	addIPSet(store, "notDst0", "5.6.7.8")
	addIPSet(store, "notDst1", "5.6.7.8", srcAddr)
	reqCache, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())
	Expect(match(rule, reqCache, "")).To(BeTrue())
}

// Test namespace selectors are handled correctly
func TestMatchRuleNamespaceSelectors(t *testing.T) {
	RegisterTestingT(t)

	rule := &proto.Rule{
		OriginalSrcNamespaceSelector: "place == 'src'",
		OriginalDstNamespaceSelector: "place == 'dst'",
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/src/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/dst/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}

	store := policystore.NewPolicyStore()
	id := proto.NamespaceID{Name: "src"}
	store.NamespaceByID[id] = &proto.NamespaceUpdate{Id: &id, Labels: map[string]string{"place": "src"}}
	id = proto.NamespaceID{Name: "dst"}
	store.NamespaceByID[id] = &proto.NamespaceUpdate{Id: &id, Labels: map[string]string{"place": "dst"}}
	reqCache, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())
	Expect(match(rule, reqCache, "")).To(BeTrue())
}

// Test that rules only match same namespace if pod selector or service account is set
func TestMatchRulePolicyNamespace(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}

	store := policystore.NewPolicyStore()
	reqCache, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())

	// With pod selector
	rule := &proto.Rule{
		OriginalSrcSelector: "has(app)",
	}
	Expect(match(rule, reqCache, "different")).To(BeFalse())
	Expect(match(rule, reqCache, "testns")).To(BeTrue())

	// With no pod selector or SA selector
	rule.OriginalSrcSelector = ""
	Expect(match(rule, reqCache, "different")).To(BeTrue())

	// With SA selector
	rule.SrcServiceAccountMatch = &proto.ServiceAccountMatch{Names: []string{"sam"}}
	Expect(match(rule, reqCache, "different")).To(BeFalse())
	Expect(match(rule, reqCache, "testns")).To(BeTrue())
}

func addIPSet(store *policystore.PolicyStore, id string, addr ...string) {
	s := policystore.NewIPSet(proto.IPSetUpdate_IP)
	for _, a := range addr {
		s.AddString(a)
	}
	store.IPSetByID[id] = s
}

// Test that rules match L4 protocol.
func TestMatchL4Protocol(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}

	store := policystore.NewPolicyStore()
	reqCache, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())

	// With empty rule and default request.
	rule := &proto.Rule{}
	Expect(match(rule, reqCache, "testns")).To(BeTrue())

	// With empty rule and UDP request
	req.GetAttributes().GetDestination().Address = socketAddressProtocolUDP
	Expect(match(rule, reqCache, "testns")).To(BeTrue())
	req.GetAttributes().GetDestination().Address = nil

	// With Protocol=TCP rule and default request
	rule.Protocol = &proto.Protocol{
		&proto.Protocol_Name{
			Name: "TCP",
		},
	}
	Expect(match(rule, reqCache, "testns")).To(BeTrue())
	rule.Protocol = nil

	// With Protocol=6 rule and default request
	rule.Protocol = &proto.Protocol{
		&proto.Protocol_Number{
			Number: 6,
		},
	}
	Expect(match(rule, reqCache, "testns")).To(BeTrue())
	rule.Protocol = nil

	// With Protocol=17 rule and default request
	rule.Protocol = &proto.Protocol{
		&proto.Protocol_Number{
			Number: 17,
		},
	}
	Expect(match(rule, reqCache, "testns")).To(BeFalse())
	rule.Protocol = nil

	// With Protocol!=UDP rule and default request
	rule.NotProtocol = &proto.Protocol{
		&proto.Protocol_Name{
			Name: "UDP",
		},
	}
	Expect(match(rule, reqCache, "testns")).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol!=6 rule and TCP request
	rule.NotProtocol = &proto.Protocol{
		&proto.Protocol_Number{
			Number: 6,
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolTCP
	Expect(match(rule, reqCache, "testns")).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol!=TCP and Protocol == TCP rule and TCP request
	rule.NotProtocol = &proto.Protocol{
		&proto.Protocol_Name{
			Name: "TCP",
		},
	}
	rule.Protocol = &proto.Protocol{
		&proto.Protocol_Name{
			Name: "TCP",
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolTCP
	Expect(match(rule, reqCache, "testns")).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol!=TCP and Protocol == TCP rule and UDP request
	rule.NotProtocol = &proto.Protocol{
		&proto.Protocol_Name{
			Name: "TCP",
		},
	}
	rule.Protocol = &proto.Protocol{
		&proto.Protocol_Name{
			Name: "TCP",
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolUDP
	Expect(match(rule, reqCache, "testns")).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil
}
