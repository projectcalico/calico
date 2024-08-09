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
	uut, err := NewRequestCache(policystore.NewPolicyStore(), req)
	Expect(err).To(Succeed())
	Expect(uut.SourcePeer().Name).To(Equal(""))
	Expect(uut.SourcePeer().Namespace).To(Equal(""))
	Expect(uut.DestinationPeer().Name).To(Equal(""))
	Expect(uut.DestinationPeer().Namespace).To(Equal(""))
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
	_, err := NewRequestCache(policystore.NewPolicyStore(), req)
	Expect(err).ToNot(Succeed())
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
	uut, err := NewRequestCache(policystore.NewPolicyStore(), req)
	Expect(err).To(Succeed())
	Expect(uut.SourcePeer().Name).To(Equal("bacon"))
	Expect(uut.SourcePeer().Namespace).To(Equal("sandwich"))
	Expect(uut.SourcePeer().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2"}))
	Expect(uut.DestinationPeer().Name).To(Equal("ham"))
	Expect(uut.DestinationPeer().Namespace).To(Equal("sub"))
	Expect(uut.DestinationPeer().Labels).To(Equal(map[string]string{"k3": "v3", "k4": "v4"}))
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
	id := types.ServiceAccountID{Name: "bacon", Namespace: "sandwich"}
	protoID := types.ServiceAccountIDToProto(id)
	store.ServiceAccountByID[id] = &proto.ServiceAccountUpdate{
		Id:     protoID,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	id = types.ServiceAccountID{Name: "ham", Namespace: "sub"}
	protoID = types.ServiceAccountIDToProto(id)
	store.ServiceAccountByID[id] = &proto.ServiceAccountUpdate{
		Id:     protoID,
		Labels: map[string]string{"k7": "v7", "k8": "v8"},
	}
	uut, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())
	Expect(uut.SourcePeer().Name).To(Equal("bacon"))
	Expect(uut.SourcePeer().Namespace).To(Equal("sandwich"))
	Expect(uut.SourcePeer().Labels).To(Equal(map[string]string{"k5": "v5", "k6": "v6"}))
	Expect(uut.DestinationPeer().Name).To(Equal("ham"))
	Expect(uut.DestinationPeer().Namespace).To(Equal("sub"))
	Expect(uut.DestinationPeer().Labels).To(Equal(map[string]string{"k7": "v7", "k8": "v8"}))
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
	id := types.ServiceAccountID{Name: "bacon", Namespace: "sandwich"}
	protoID := types.ServiceAccountIDToProto(id)
	store.ServiceAccountByID[id] = &proto.ServiceAccountUpdate{
		Id:     protoID,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	id = types.ServiceAccountID{Name: "ham", Namespace: "sub"}
	protoID = types.ServiceAccountIDToProto(id)
	store.ServiceAccountByID[id] = &proto.ServiceAccountUpdate{
		Id:     protoID,
		Labels: map[string]string{"k7": "v7", "k8": "v8"},
	}
	uut, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())
	Expect(uut.SourcePeer().Name).To(Equal("bacon"))
	Expect(uut.SourcePeer().Namespace).To(Equal("sandwich"))
	Expect(uut.SourcePeer().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2", "k5": "v5", "k6": "v6"}))
	Expect(uut.DestinationPeer().Name).To(Equal("ham"))
	Expect(uut.DestinationPeer().Namespace).To(Equal("sub"))
	Expect(uut.DestinationPeer().Labels).To(Equal(map[string]string{"k3": "v3", "k4": "v4", "k7": "v7", "k8": "v8"}))
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
	_, err := NewRequestCache(policystore.NewPolicyStore(), req)
	Expect(err).ToNot(Succeed())
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
	id := types.NamespaceID{Name: "sandwich"}
	protoID := types.NamespaceIDToProto(id)
	store.NamespaceByID[id] = &proto.NamespaceUpdate{
		Id:     protoID,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	id = types.NamespaceID{Name: "sub"}
	protoID = types.NamespaceIDToProto(id)
	store.NamespaceByID[id] = &proto.NamespaceUpdate{
		Id:     protoID,
		Labels: map[string]string{"k7": "v7", "k8": "v8"},
	}
	uut, err := NewRequestCache(store, req)
	Expect(err).To(Succeed())
	Expect(uut.SourceNamespace().Name).To(Equal("sandwich"))
	Expect(uut.SourceNamespace().Labels).To(Equal(map[string]string{"k5": "v5", "k6": "v6"}))
	Expect(uut.DestinationNamespace().Name).To(Equal("sub"))
	Expect(uut.DestinationNamespace().Labels).To(Equal(map[string]string{"k7": "v7", "k8": "v8"}))
}
