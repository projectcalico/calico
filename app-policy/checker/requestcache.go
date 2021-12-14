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
	"fmt"
	"regexp"
	"sync"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/proto"
)

// requestCache contains the CheckRequest and cached copies of computed information about the request
type requestCache struct {
	Request              *authz.CheckRequest
	store                *policystore.PolicyStore
	source               *peer
	destination          *peer
	sourceNamespace      *namespace
	destinationNamespace *namespace
}

// peer is derived from the request Service Account and any label information we have about the account
// in the PolicyStore
type peer struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

type namespace struct {
	Name   string
	Labels map[string]string
}

// SPIFFE_ID_PATTERN is a regular expression to match SPIFFE ID URIs, e.g. spiffe://cluster.local/ns/default/sa/foo
const SPIFFE_ID_PATTERN = "^spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)$"

var spiffeIdRegExp *regexp.Regexp
var spiffeIdRegExpOnce = sync.Once{}

func NewRequestCache(store *policystore.PolicyStore, req *authz.CheckRequest) (*requestCache, error) {
	r := &requestCache{Request: req, store: store}
	err := r.initPeers()
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SourcePeer returns the cached source peer.
func (r *requestCache) SourcePeer() peer {
	return *r.source
}

// DestinationPeer returns the cached destination peer.
func (r *requestCache) DestinationPeer() peer {
	return *r.destination
}

func (r *requestCache) SourceNamespace() namespace {
	if r.sourceNamespace != nil {
		return *r.sourceNamespace
	}
	src := r.initNamespace(r.source.Namespace)
	r.sourceNamespace = src
	return *src
}

func (r *requestCache) DestinationNamespace() namespace {
	if r.destinationNamespace != nil {
		return *r.destinationNamespace
	}
	dst := r.initNamespace(r.destination.Namespace)
	r.destinationNamespace = dst
	return *dst
}

// initPeers initializes the source and destination peers.
func (r *requestCache) initPeers() error {
	src, err := r.initPeer(r.Request.GetAttributes().GetSource())
	if err != nil {
		return err
	}
	r.source = src
	dst, err := r.initPeer(r.Request.GetAttributes().GetDestination())
	if err != nil {
		return err
	}
	r.destination = dst
	return nil
}

func (r *requestCache) initPeer(aPeer *authz.AttributeContext_Peer) (*peer, error) {
	peer, err := parseSpiffeID(aPeer.GetPrincipal())
	if err != nil {
		return nil, err
	}
	// Copy any labels from the request.
	peer.Labels = make(map[string]string)
	for k, v := range aPeer.GetLabels() {
		peer.Labels[k] = v
	}

	// If the service account is in the store, copy labels over.
	id := proto.ServiceAccountID{Name: peer.Name, Namespace: peer.Namespace}
	msg, ok := r.store.ServiceAccountByID[id]
	if ok {
		for k, v := range msg.GetLabels() {
			peer.Labels[k] = v
		}
	}
	return &peer, nil
}

func (r *requestCache) initNamespace(name string) *namespace {
	ns := &namespace{Name: name}
	// If the namespace is in the store, copy labels over.
	id := proto.NamespaceID{Name: name}
	msg, ok := r.store.NamespaceByID[id]
	if ok {
		ns.Labels = make(map[string]string)
		for k, v := range msg.GetLabels() {
			ns.Labels[k] = v
		}
	}
	return ns
}

// GetIPSet returns the given IPSet from the store.
func (r *requestCache) GetIPSet(ipset string) policystore.IPSet {
	s, ok := r.store.IPSetByID[ipset]
	if !ok {
		log.WithField("ipset", ipset).Panic("could not find IP set")
	}
	return s
}

// parseSpiffeId parses an Istio SPIFFE ID and extracts the service account name and namespace.
func parseSpiffeID(id string) (peer peer, err error) {
	if id == "" {
		log.Debug("empty spiffe/plain text request.")
		// Assume this is plain text.
		return peer, nil
	}
	// Init the regexp the first time this is called, and store it in the package namespace.
	spiffeIdRegExpOnce.Do(func() {
		spiffeIdRegExp, _ = regexp.Compile(SPIFFE_ID_PATTERN)
	})
	match := spiffeIdRegExp.FindStringSubmatch(id)
	if match == nil {
		err = fmt.Errorf("expected match %s, got %s", SPIFFE_ID_PATTERN, id)
	} else {
		peer.Name = match[2]
		peer.Namespace = match[1]
	}
	return
}
