// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.

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
	"io"
	"testing"
	"time"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/logrusr"
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

// Identity is resolved once per request, not once per rule: the match functions ask for the
// peer and namespace of both sides for every rule, and resolving parses the SPIFFE ID and
// copies two label maps.
func TestIdentityResolvedOncePerRequest(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/sandwich/sa/bacon",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/salad/sa/lettuce",
		},
	}}
	uut := NewRequestCache(policystore.NewPolicyStore(), NewCheckRequestToFlowAdapter(req))

	Expect(uut.getSrcPeer().Name).To(Equal("bacon"))
	Expect(uut.getDstPeer().Name).To(Equal("lettuce"))
	Expect(uut.getSrcNamespace().Name).To(Equal("sandwich"))
	Expect(uut.getDstNamespace().Name).To(Equal("salad"))

	// Repeated lookups return the memoized values rather than resolving again.
	Expect(uut.getSrcPeer()).To(BeIdenticalTo(uut.getSrcPeer()))
	Expect(uut.getDstPeer()).To(BeIdenticalTo(uut.getDstPeer()))
	Expect(uut.getSrcNamespace()).To(BeIdenticalTo(uut.getSrcNamespace()))
	Expect(uut.getDstNamespace()).To(BeIdenticalTo(uut.getDstNamespace()))
	Expect(uut.getSrcPeer()).NotTo(BeIdenticalTo(uut.getDstPeer()))
}

// A principal that is not a SPIFFE ID leaves the side unidentified. Dikastes falls back on IP
// addresses in that case, so rules without identity criteria still match.
func TestUnparseablePrincipalIsMemoized(t *testing.T) {
	RegisterTestingT(t)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "http://foo.bar.com/ns/sandwich/sa/bacon",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "",
		},
	}}
	uut := NewRequestCache(policystore.NewPolicyStore(), NewCheckRequestToFlowAdapter(req))

	Expect(uut.getSrcPeer()).To(BeNil())
	Expect(uut.getSrcNamespace()).To(BeNil())
	// A nil peer must not be mistaken for "not resolved yet", or every rule retries the parse
	// and re-logs the failure.
	Expect(uut.identities[sourceSide].resolved).To(BeTrue())
	Expect(matchServiceAccounts(nil, uut.getSrcPeer())).To(BeTrue())
}

// Repeated failures on the evaluation path are rate limited: one line, then a count of what
// was suppressed. Without this a single dangling IP set reference logs once per rule, for
// every request.
func TestEvalPathWarningsAreRateLimited(t *testing.T) {
	RegisterTestingT(t)

	logger := log.StandardLogger()
	oldLevel, oldOut := logger.GetLevel(), logger.Out
	counter := &entryCounter{}
	hooks := make(log.LevelHooks)
	hooks.Add(counter)
	oldHooks := logger.ReplaceHooks(hooks)
	savedLogger := rlogIPSetMissing
	defer func() {
		logger.SetLevel(oldLevel)
		logger.SetOutput(oldOut)
		logger.ReplaceHooks(oldHooks)
		rlogIPSetMissing = savedLogger
	}()
	logger.SetLevel(log.WarnLevel)
	logger.SetOutput(io.Discard)
	// A long interval with no burst allowance: the first message is written, the rest are
	// counted.
	rlogIPSetMissing = logrusr.NewRateLimitedLogger(logrusr.OptInterval(time.Hour))

	uut := NewRequestCache(policystore.NewPolicyStore(), NewCheckRequestToFlowAdapter(
		&authz.CheckRequest{Attributes: &authz.AttributeContext{}}))
	for range 100 {
		Expect(uut.getIPSet("missing-set")).To(BeNil())
	}

	Expect(counter.entries).To(HaveLen(1), "expected one emitted warning for 100 misses")
	Expect(counter.entries[0].Message).To(ContainSubstring("missing-set"))
	Expect(counter.entries[0].Data).NotTo(HaveKey("logsSkipped"))

	// The suppressed count surfaces on the next line that is allowed through, so the storm is
	// still visible in the log.
	rlogIPSetMissing.Force().Warnf("IPSet not found: %s", "missing-set")
	Expect(counter.entries).To(HaveLen(2))
	Expect(counter.entries[1].Data).To(HaveKeyWithValue("logsSkipped", 99))
}

// entryCounter collects the log entries written during a test.
type entryCounter struct {
	entries []*log.Entry
}

func (c *entryCounter) Levels() []log.Level { return log.AllLevels }

func (c *entryCounter) Fire(e *log.Entry) error {
	c.entries = append(c.entries, e)
	return nil
}
