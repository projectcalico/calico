package checker

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/proto"

	authz "github.com/envoyproxy/data-plane-api/api/auth"
)

// Successful parse should return name and namespace.
func TestParseSpiffeIdOk(t *testing.T) {
	RegisterTestingT(t)

	id := "spiffe://foo.bar.com/ns/sandwich/sa/bacon"
	peer, err := parseSpiffeID(id)
	Expect(peer.Name).To(Equal("bacon"))
	Expect(peer.Namespace).To(Equal("sandwich"))
	Expect(err).To(BeNil())
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
	}}
	uut := NewRequestCache(policystore.NewPolicyStore(), req)
	Expect(uut.InitSource()).ToNot(Succeed())
}

func TestInitSourceRequestLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{"k1": "v1", "k2": "v2"},
		},
	}}
	uut := NewRequestCache(policystore.NewPolicyStore(), req)
	Expect(uut.InitSource()).To(Succeed())
	Expect(uut.Source().Name).To(Equal("bacon"))
	Expect(uut.Source().Namespace).To(Equal("sandwich"))
	Expect(uut.Source().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2"}))
}

func TestInitSourceStoreLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{},
		},
	}}
	store := policystore.NewPolicyStore()
	id := proto.ServiceAccountID{Name: "bacon", Namespace: "sandwich"}
	store.ServiceAccountByID[id] = &proto.ServiceAccountUpdate{
		Id:     &id,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	uut := NewRequestCache(store, req)
	Expect(uut.InitSource()).To(Succeed())
	Expect(uut.Source().Name).To(Equal("bacon"))
	Expect(uut.Source().Namespace).To(Equal("sandwich"))
	Expect(uut.Source().Labels).To(Equal(map[string]string{"k5": "v5", "k6": "v6"}))
}

func TestInitSourceBothLabels(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://foo.bar.com/ns/sandwich/sa/bacon",
			Labels:    map[string]string{"k1": "v1", "k2": "v2", "k5": "v5old"},
		},
	}}
	store := policystore.NewPolicyStore()
	id := proto.ServiceAccountID{Name: "bacon", Namespace: "sandwich"}
	store.ServiceAccountByID[id] = &proto.ServiceAccountUpdate{
		Id:     &id,
		Labels: map[string]string{"k5": "v5", "k6": "v6"},
	}
	uut := NewRequestCache(store, req)
	Expect(uut.InitSource()).To(Succeed())
	Expect(uut.Source().Name).To(Equal("bacon"))
	Expect(uut.Source().Namespace).To(Equal("sandwich"))
	Expect(uut.Source().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2", "k5": "v5", "k6": "v6"}))

	// Repeat to test Idempotency of InitSource()
	Expect(uut.InitSource()).To(Succeed())
	Expect(uut.Source().Name).To(Equal("bacon"))
	Expect(uut.Source().Namespace).To(Equal("sandwich"))
	Expect(uut.Source().Labels).To(Equal(map[string]string{"k1": "v1", "k2": "v2", "k5": "v5", "k6": "v6"}))
}

func TestSourceBeforeInitSource(t *testing.T) {
	RegisterTestingT(t)

	uut := NewRequestCache(policystore.NewPolicyStore(), &authz.CheckRequest{})
	Expect(func() { _ = uut.Source() }).To(Panic())
}
