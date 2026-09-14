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
	"slices"
	"sync"
	"testing"
	"time"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// TestGetIPSetAggregatesMisses covers the wiring rather than the aggregator itself (which has its
// own tests in libcalico-go/lib/logutils): a store miss must still return nil, and the repeated
// misses a single flow provokes must collapse to one line naming the sets that went missing, not
// one line each.
func TestGetIPSetAggregatesMisses(t *testing.T) {
	RegisterTestingT(t)

	capture, restore := captureCheckerLogs()
	defer restore()

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source:      &authz.AttributeContext_Peer{Principal: ""},
		Destination: &authz.AttributeContext_Peer{Principal: ""},
	}}
	rc := NewRequestCache(policystore.NewPolicyStore(), NewCheckRequestToFlowAdapter(req))

	// The store is empty, so every lookup misses. Aggregation changes only the logging: the value
	// getIPSet returns is what it always was.
	for range 100 {
		Expect(rc.getIPSet("missing-a")).To(BeNil())
		Expect(rc.getIPSet("missing-b")).To(BeNil())
	}

	// The first miss is reported as it happens, carrying only itself.
	lines := capture.snapshot()
	Expect(lines).To(HaveLen(1))
	Expect(lines[0].Message).To(Equal("IPSet not found"))
	Expect(lines[0].Level).To(Equal(missingIPSetsLevel))
	Expect(lines[0].Data).To(HaveKeyWithValue("ipsets", logutils.AggregatedValues{"missing-a"}))

	// The other 199 fold into the window behind it, which closes on its own and names both sets that
	// went missing. Without aggregation these 200 misses were 200 lines.
	Eventually(capture.snapshot, "5s", "10ms").Should(HaveLen(2))
	lines = capture.snapshot()
	Expect(lines[1].Data).To(HaveKeyWithValue("ipsets", logutils.AggregatedValues{"missing-a", "missing-b"}))
	Expect(lines[1].Data).To(HaveKeyWithValue("totalEvents", 199))
}

// TestAggregatedConditionLevels pins the severities themselves. captureCheckerLogs builds its
// stand-ins from these same constants, so the other tests follow production wherever it goes;
// this one is what makes moving it a deliberate edit rather than a silent one.
func TestAggregatedConditionLevels(t *testing.T) {
	RegisterTestingT(t)

	Expect(missingIPSetsLevel).To(Equal(log.WarnLevel))
	Expect(unparseablePrincipalsLevel).To(Equal(log.ErrorLevel))
}

// TestGetIPSetHit confirms the hit path is untouched: a set that is present is returned as-is and
// logs nothing.
func TestGetIPSetHit(t *testing.T) {
	RegisterTestingT(t)

	capture, restore := captureCheckerLogs()
	defer restore()

	store := policystore.NewPolicyStore()
	store.IPSetByID["present"] = policystore.NewIPSet(proto.IPSetUpdate_IP)

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source:      &authz.AttributeContext_Peer{Principal: ""},
		Destination: &authz.AttributeContext_Peer{Principal: ""},
	}}
	rc := NewRequestCache(store, NewCheckRequestToFlowAdapter(req))

	Expect(rc.getIPSet("present")).NotTo(BeNil())
	Expect(capture.snapshot()).To(BeEmpty())
}

// captureCheckerLogs points this package's aggregating loggers at one capturing logger, and returns
// that capture alongside the func that puts the originals back. They are package-level because an
// aggregation window is shared process-wide, so a test driving the real ones would leak both their
// window state and their output into every other test in the package.
//
// The interval is cut to a fraction of the production five minutes so that a test can watch a window
// close without waiting on one.
func captureCheckerLogs() (*captureLogger, func()) {
	capture := newCaptureLogger()
	savedIPSets, savedPrincipals := missingIPSets, unparseablePrincipals
	// Built from the production levels, not from restated literals: without OptAggregationLevel
	// both would default to Warn, and the principal site would be exercised a level below the one
	// it reports at. Taking the constants means a change to either severity reaches these tests.
	missingIPSets = logutils.NewAggregatingLogger("IPSet not found", "ipsets",
		logutils.OptAggregationLogger(capture.Logger), logutils.OptAggregationInterval(captureInterval),
		logutils.OptAggregationLevel(missingIPSetsLevel))
	unparseablePrincipals = logutils.NewAggregatingLogger("failed to parse principal", "principals",
		logutils.OptAggregationLogger(capture.Logger), logutils.OptAggregationInterval(captureInterval),
		logutils.OptAggregationLevel(unparseablePrincipalsLevel))
	return capture, func() {
		missingIPSets, unparseablePrincipals = savedIPSets, savedPrincipals
	}
}

// captureInterval is long enough that a test's whole burst lands in one window, short enough that
// waiting for that window to close costs nothing worth measuring.
const captureInterval = 100 * time.Millisecond

// captureLogger is a logrus logger recording what it was asked to write, so a test can assert on
// it. Windows close on a timer, so lines arrive on a goroutine of their own; the mutex is what lets
// a test read them while that is happening.
type captureLogger struct {
	*log.Logger
	mu    sync.Mutex
	lines []*log.Entry
}

func newCaptureLogger() *captureLogger {
	c := &captureLogger{Logger: log.New()}
	c.SetOutput(io.Discard)
	c.SetLevel(log.DebugLevel)
	c.AddHook(c)
	return c
}

func (c *captureLogger) Levels() []log.Level { return log.AllLevels }

func (c *captureLogger) Fire(e *log.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, e)
	return nil
}

// snapshot returns the lines written so far. Gomega polls it, so it must copy rather than hand out
// the slice the writer is appending to.
func (c *captureLogger) snapshot() []*log.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.lines)
}

// TestInitPeerAggregatesParseFailures covers the other converted site. A peer whose principal will
// not parse provokes the same failure on every flow it sources, so those must collapse to one line
// naming the principals rather than one line per flow. Aggregating on the principal is what makes
// dropping the error harmless - parseSpiffeID's only failure is a function of the principal.
func TestInitPeerAggregatesParseFailures(t *testing.T) {
	RegisterTestingT(t)

	capture, restore := captureCheckerLogs()
	defer restore()

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source:      &authz.AttributeContext_Peer{Principal: ""},
		Destination: &authz.AttributeContext_Peer{Principal: ""},
	}}
	rc := NewRequestCache(policystore.NewPolicyStore(), NewCheckRequestToFlowAdapter(req))

	// Neither principal is a SPIFFE ID, so every call fails to parse and returns nil.
	for range 100 {
		Expect(rc.initPeer("not-a-spiffe-id", nil)).To(BeNil())
		Expect(rc.initPeer("spiffe://missing-the-rest", nil)).To(BeNil())
	}

	// The first failure is reported as it happens, naming the principal rather than an error string.
	lines := capture.snapshot()
	Expect(lines).To(HaveLen(1))
	Expect(lines[0].Message).To(Equal("failed to parse principal"))
	Expect(lines[0].Level).To(Equal(unparseablePrincipalsLevel))
	Expect(lines[0].Data).To(HaveKeyWithValue("principals", logutils.AggregatedValues{"not-a-spiffe-id"}))

	// The remaining 199 fold into the window behind it, which closes on its own naming both bad
	// principals.
	Eventually(capture.snapshot, "5s", "10ms").Should(HaveLen(2))
	lines = capture.snapshot()
	Expect(lines[1].Data).To(HaveKeyWithValue("principals",
		logutils.AggregatedValues{"not-a-spiffe-id", "spiffe://missing-the-rest"}))
	Expect(lines[1].Data).To(HaveKeyWithValue("totalEvents", 199))
}

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
