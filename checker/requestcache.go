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

	authz "github.com/envoyproxy/data-plane-api/api/auth"
	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/proto"
)

// requestCache contains the CheckRequest and cached copies of computed information about the request
type requestCache struct {
	Request     *authz.CheckRequest
	store       *policystore.PolicyStore
	source      *Peer
	destination *Peer
}

type Peer struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

// SPIFFE_ID_PATTERN is a regular expression to match SPIFFE ID URIs, e.g. spiffe://cluster.local/ns/default/sa/foo
const SPIFFE_ID_PATTERN = "^spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)$"

var spiffeIdRegExp *regexp.Regexp

func NewRequestCache(store *policystore.PolicyStore, req *authz.CheckRequest) *requestCache {
	return &requestCache{Request: req, store: store}
}

// Source returns the cached source Peer. You must call Init() or InitSource() before calling this method.
func (r *requestCache) Source() Peer {
	if r.source == nil {
		panic("Called Source() before InitSource()")
	}
	return *r.source
}

// Destination returns the cached destination Peer. You must call Init() or InitDestination() before calling this
// method.
func (r *requestCache) Destination() Peer {
	if r.destination == nil {
		panic("Called Destination() before InitDestination()")
	}
	return *r.destination
}

// InitSource initializes the source peer. It parses the SPIFFE ID of the source peer, and stores the result.  It
// accesses labels from the store and merges them with the request (if any).  Idempotent.
func (r *requestCache) InitSource() error {
	if r.source != nil {
		return nil
	}
	peer, err := r.initPeer(r.Request.GetAttributes().GetSource())
	if err != nil {
		return err
	}
	r.source = peer
	return nil
}

// InitSource initializes the destination peer. It parses the SPIFFE ID of the destination peer, and stores the result.
// It accesses labels from the store and merges them with the request (if any).  Idempotent.
func (r *requestCache) InitDestination() error {
	if r.destination != nil {
		return nil
	}
	peer, err := r.initPeer(r.Request.GetAttributes().GetDestination())
	if err != nil {
		return err
	}
	r.destination = peer
	return nil
}

// InitPeers initializes the source and destination peers.
func (r *requestCache) InitPeers() error {
	err := r.InitSource()
	if err != nil {
		return err
	}
	return r.InitDestination()
}

func (r *requestCache) initPeer(aPeer *authz.AttributeContext_Peer) (*Peer, error) {
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

// parseSpiffeId parses an Istio SPIFFE ID and extracts the service account name and namespace.
func parseSpiffeID(id string) (peer Peer, err error) {
	// Init the regexp the first time this is called, and store it in the package namespace.
	if spiffeIdRegExp == nil {
		// We drop the returned error here, since we are compiling
		spiffeIdRegExp, _ = regexp.Compile(SPIFFE_ID_PATTERN)
	}
	match := spiffeIdRegExp.FindStringSubmatch(id)
	if match == nil {
		err = fmt.Errorf("expected match %s, got %s", SPIFFE_ID_PATTERN, id)
	} else {
		peer.Name = match[2]
		peer.Namespace = match[1]
	}
	return
}
