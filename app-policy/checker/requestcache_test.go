// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checker

import (
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// Successful parse should return name and namespace.
func TestParseSpiffeIdOk(t *testing.T) {
	RegisterTestingT(t)

	id := "spiffe://foo.bar.com/ns/sandwich/sa/bacon"
	peer, err := parseSpiffeID(id)
	Expect(peer.Name).To(Equal("bacon"))
	Expect(peer.Namespace).To(Equal("sandwich"))
	Expect(err).To(BeNil())

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "",
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	uut := NewRequestCache(policystore.NewPolicyStore(), flow)
	Expect(uut).NotTo(BeNil())
	Expect(uut.getSrcPeer().Name).To(Equal(""))
	Expect(uut.getSrcPeer().Namespace).To(Equal(""))
	Expect(uut.getDstPeer().Name).To(Equal(""))
	Expect(uut.getDstPeer().Namespace).To(Equal(""))
}

// Unsuccessful parse should return an error.
func TestParseSpiffeIdFail(t *testing.T) {
	RegisterTestingT(t)

	id := "http://foo.bar.com/ns/sandwich/sa/bacon"
	_, err := parseSpiffeID(id)
	Expect(err).ToNot(BeNil())
}

func TestInitSourceBadSpiffe(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "http://foo.bar.com/ns/sandwich/sa/bacon",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sub/sa/ham",
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	rc := NewRequestCache(policystore.NewPolicyStore(), flow)
	Expect(rc.getSrcPeer()).To(BeNil())
	Expect(rc.getDstPeer()).To(Equal(&peer{Name: "ham", Namespace: "sub", Labels: map[string]string{}}))
}

func TestInitPeerRequestLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{"k1": "v1", "k2": "v2"},
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sub/sa/ham",
			Labels:    map[string]string{"k3": "v3", "k4": "v4"},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	uut := NewRequestCache(policystore.NewPolicyStore(), flow)
	Expect(uut.getSrcPeer().Name).To(Equal("bacon"))
	Expect(uut.getSrcPeer().Namespace).To(Equal("sandwich"))
	Expect(uut.getSrcPeer().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2"}))
	Expect(uut.getDstPeer().Name).To(Equal("ham"))
	Expect(uut.getDstPeer().Namespace).To(Equal("sub"))
	Expect(uut.getDstPeer().Labels).To(Equal(map[string]string{"k3": "v3", "k4": "v4"}))
}

func TestInitPeerStoreLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{},
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sub/sa/ham",
			Labels:    map[string]string{},
		},
	}}
	store := policystore.NewPolicyStore()
	id := proto.ServiceAccountID{Name: "bacon", Namespace: "sandwich"}
	store.ServiceAccountByID[types.ProtoToServiceAccountID(&id)] = &proto.ServiceAccountUpdate{
		Id:     &id,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	id = proto.ServiceAccountID{Name: "ham", Namespace: "sub"}
	store.ServiceAccountByID[types.ProtoToServiceAccountID(&id)] = &proto.ServiceAccountUpdate{
		Id:     &id,
		Labels: map[string]string{"k7": "v7", "k8": "v8"},
	}
	flow := NewCheckRequestToFlowAdapter(req)
	uut := NewRequestCache(store, flow)
	Expect(uut.getSrcPeer().Name).To(Equal("bacon"))
	Expect(uut.getSrcPeer().Namespace).To(Equal("sandwich"))
	Expect(uut.getSrcPeer().Labels).To(Equal(map[string]string{"k5": "v5", "k6": "v6"}))
	Expect(uut.getDstPeer().Name).To(Equal("ham"))
	Expect(uut.getDstPeer().Namespace).To(Equal("sub"))
	Expect(uut.getDstPeer().Labels).To(Equal(map[string]string{"k7": "v7", "k8": "v8"}))
}

func TestInitPeerBothLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{"k1": "v1", "k2": "v2", "k5": "v5old"},
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sub/sa/ham",
			Labels:    map[string]string{"k3": "v3", "k4": "v4", "k7": "v7old"},
		},
	}}
	store := policystore.NewPolicyStore()
	id := proto.ServiceAccountID{Name: "bacon", Namespace: "sandwich"}
	store.ServiceAccountByID[types.ProtoToServiceAccountID(&id)] = &proto.ServiceAccountUpdate{
		Id:     &id,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	id = proto.ServiceAccountID{Name: "ham", Namespace: "sub"}
	store.ServiceAccountByID[types.ProtoToServiceAccountID(&id)] = &proto.ServiceAccountUpdate{
		Id:     &id,
		Labels: map[string]string{"k7": "v7", "k8": "v8"},
	}
	flow := NewCheckRequestToFlowAdapter(req)
	uut := NewRequestCache(store, flow)
	Expect(uut.getSrcPeer().Name).To(Equal("bacon"))
	Expect(uut.getSrcPeer().Namespace).To(Equal("sandwich"))
	Expect(uut.getSrcPeer().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2", "k5": "v5", "k6": "v6"}))
	Expect(uut.getDstPeer().Name).To(Equal("ham"))
	Expect(uut.getDstPeer().Namespace).To(Equal("sub"))
	Expect(uut.getDstPeer().Labels).To(Equal(map[string]string{"k3": "v3", "k4": "v4", "k7": "v7", "k8": "v8"}))
}

func TestInitDestinationBadSpiffe(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{},
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "http://foo.bar.com/ns/sandwich/sa/bacon",
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)
	rc := NewRequestCache(policystore.NewPolicyStore(), flow)
	Expect(rc.getSrcPeer()).To(Equal(&peer{Name: "bacon", Namespace: "sandwich", Labels: map[string]string{}}))
	Expect(rc.getDstPeer()).To(BeNil())
}

func TestNamespaceLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sub/sa/ham",
		},
	}}
	store := policystore.NewPolicyStore()
	id := proto.NamespaceID{Name: "sandwich"}
	store.NamespaceByID[types.ProtoToNamespaceID(&id)] = &proto.NamespaceUpdate{
		Id:     &id,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	id = proto.NamespaceID{Name: "sub"}
	store.NamespaceByID[types.ProtoToNamespaceID(&id)] = &proto.NamespaceUpdate{
		Id:     &id,
		Labels: map[string]string{"k7": "v7", "k8": "v8"},
	}
	flow := NewCheckRequestToFlowAdapter(req)
	uut := NewRequestCache(store, flow)
	Expect(uut.getSrcNamespace().Name).To(Equal("sandwich"))
	Expect(uut.getSrcNamespace().Labels).To(Equal(map[string]string{"k5": "v5", "k6": "v6"}))
	Expect(uut.getDstNamespace().Name).To(Equal("sub"))
	Expect(uut.getDstNamespace().Labels).To(Equal(map[string]string{"k7": "v7", "k8": "v8"}))
}
