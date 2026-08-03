// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"maps"
	"regexp"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

const SPIFFEIDPattern = "^spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)$"

var (
	protocolMap = map[string]int{
		"icmp": 1,
		"tcp":  6,
		"udp":  17,
	}

	spiffeIdRegExp     *regexp.Regexp
	spiffeIdRegExpOnce = sync.Once{}
)

type requestCache struct {
	Flow
	store *policystore.PolicyStore

	// Memoized string forms of per-flow values. The match functions need these for
	// every rule that carries an IP set reference; recomputing them per rule dominates
	// allocation when many policies apply to an endpoint.
	srcIPStr       string
	dstIPStr       string
	dstIPProtoPort string

	// Memoized identity, indexed by flowSide. Resolving it parses a SPIFFE ID and copies
	// two label maps, and the match functions ask for it once per rule.
	identities [numFlowSides]identity
}

// flowSide identifies which end of the flow an identity belongs to.
type flowSide int

const (
	sourceSide flowSide = iota
	destSide
	numFlowSides
)

// identity is the resolved peer and namespace for one side of the flow. A nil peer means
// the side carries no principal, or one that could not be parsed; both cases match any
// rule, because Dikastes falls back on IP addresses for plain-text requests.
type identity struct {
	peer      *peer
	namespace *namespace
	resolved  bool
}

type peer struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

type namespace struct {
	Name   string
	Labels map[string]string
}

func NewRequestCache(store *policystore.PolicyStore, request Flow) *requestCache {
	return &requestCache{
		Flow:  request,
		store: store,
	}
}

// getSrcPeer returns the source peer.
func (r *requestCache) getSrcPeer() *peer {
	return r.getIdentity(sourceSide).peer
}

// getDstPeer returns the destination peer.
func (r *requestCache) getDstPeer() *peer {
	return r.getIdentity(destSide).peer
}

// getSrcNamespace returns the namespace of the source peer.
func (r *requestCache) getSrcNamespace() *namespace {
	return r.getIdentity(sourceSide).namespace
}

// getDstNamespace returns the namespace of the destination peer.
func (r *requestCache) getDstNamespace() *namespace {
	return r.getIdentity(destSide).namespace
}

// getIdentity returns the peer and namespace for one side of the flow, resolving them from
// the request and the store on first use and memoizing the result for the rest of the
// request.
func (r *requestCache) getIdentity(side flowSide) identity {
	id := &r.identities[side]
	if id.resolved {
		return *id
	}
	id.resolved = true

	principal, labels := r.GetSourcePrincipal(), r.GetSourceLabels()
	if side == destSide {
		principal, labels = r.GetDestPrincipal(), r.GetDestLabels()
	}
	if principal == nil {
		return *id
	}
	if id.peer = r.initPeer(*principal, labels); id.peer != nil {
		id.namespace = r.initNamespace(id.peer.Namespace)
	}
	return *id
}

// getSrcIPStr returns the source IP in string form, memoized across the request.
func (r *requestCache) getSrcIPStr() string {
	if r.srcIPStr == "" {
		r.srcIPStr = r.GetSourceIP().String()
	}
	return r.srcIPStr
}

// getDstIPStr returns the destination IP in string form, memoized across the request.
func (r *requestCache) getDstIPStr() string {
	if r.dstIPStr == "" {
		r.dstIPStr = r.GetDestIP().String()
	}
	return r.dstIPStr
}

// getDstIPProtoPortStr returns the destination "<IP>,<protocol>:<port>" key used for
// IP+port set matching, memoized across the request.
func (r *requestCache) getDstIPProtoPortStr() string {
	if r.dstIPProtoPort == "" {
		protocolStr := protocolMapL4[int32(r.GetProtocol())]
		r.dstIPProtoPort = fmt.Sprintf("%s,%s:%d", r.getDstIPStr(), protocolStr, r.GetDestPort())
	}
	return r.dstIPProtoPort
}

// getIPSet returns the IPSet with the given ID.
func (r *requestCache) getIPSet(id string) policystore.IPSet {
	s, ok := r.store.IPSetByID[id]
	if !ok {
		rlogIPSetMissing.Warnf("IPSet not found: %s", id)
		return nil
	}
	return s
}

// initNamespace initializes a namespace from the store.
func (r *requestCache) initNamespace(name string) *namespace {
	ns := &namespace{Name: name}
	id := proto.NamespaceID{Name: name}
	msg, ok := r.store.NamespaceByID[types.ProtoToNamespaceID(&id)]
	if ok {
		ns.Labels = make(map[string]string)
		maps.Copy(ns.Labels, msg.GetLabels())
	}
	return ns
}

// initPeer initializes the peer from the request. It first tries to parse the principal as a
// SPIFFE ID. If that fails, it falls back to plain text.
func (r *requestCache) initPeer(principal string, labels map[string]string) *peer {
	peer, err := parseSpiffeID(principal)
	if err != nil {
		rlogBadPrincipal.Errorf("failed to parse principal: %v", err)
		return nil
	}
	peer.Labels = make(map[string]string)
	maps.Copy(peer.Labels, labels)
	id := proto.ServiceAccountID{Name: peer.Name, Namespace: peer.Namespace}
	msg, ok := r.store.ServiceAccountByID[types.ProtoToServiceAccountID(&id)]
	if ok {
		maps.Copy(peer.Labels, msg.GetLabels())
	}
	return &peer
}

// parseSpiffeID parses a SPIFFE ID into a peer struct.
func parseSpiffeID(id string) (p peer, err error) {
	if id == "" {
		log.Debug("empty spiffe/plain text request")
		return p, nil
	}
	spiffeIdRegExpOnce.Do(func() {
		spiffeIdRegExp, _ = regexp.Compile(SPIFFEIDPattern)
	})
	match := spiffeIdRegExp.FindStringSubmatch(id)
	if match == nil {
		err = fmt.Errorf("expected match %s, got %s", SPIFFEIDPattern, id)
	} else {
		p.Name = match[2]
		p.Namespace = match[1]
	}
	return
}
