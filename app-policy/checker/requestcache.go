// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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
	if principal := r.GetSourcePrincipal(); principal != nil {
		return r.initPeer(*principal, r.GetSourceLabels())
	}

	return nil
}

// getDstPeer returns the destination peer.
func (r *requestCache) getDstPeer() *peer {
	if principal := r.GetDestPrincipal(); principal != nil {
		return r.initPeer(*principal, r.GetDestLabels())
	}

	return nil
}

// getSourceNamespace returns the namespace of the source peer.
func (r *requestCache) getSrcNamespace() *namespace {
	if peer := r.getSrcPeer(); peer != nil {
		return r.initNamespace(peer.Namespace)
	}

	return nil
}

// getDstNamespace returns the namespace of the destination peer.
func (r *requestCache) getDstNamespace() *namespace {
	if peer := r.getDstPeer(); peer != nil {
		return r.initNamespace(peer.Namespace)

	}

	return nil
}

// getIPSet returns the IPSet with the given ID.
func (r *requestCache) getIPSet(id string) policystore.IPSet {
	s, ok := r.store.IPSetByID[id]
	if !ok {
		log.WithField("ipset", id).Warn("IPSet not found")
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
		for k, v := range msg.GetLabels() {
			ns.Labels[k] = v
		}
	}
	return ns
}

// initPeer initializes the peer from the request. It first tries to parse the principal as a
// SPIFFE ID. If that fails, it falls back to plain text.
func (r *requestCache) initPeer(principal string, labels map[string]string) *peer {
	peer, err := parseSpiffeID(principal)
	if err != nil {
		log.WithError(err).Error("failed to parse source principal")
		return nil
	}
	peer.Labels = make(map[string]string)
	for k, v := range labels {
		peer.Labels[k] = v
	}
	id := proto.ServiceAccountID{Name: peer.Name, Namespace: peer.Namespace}
	msg, ok := r.store.ServiceAccountByID[types.ProtoToServiceAccountID(&id)]
	if ok {
		for k, v := range msg.GetLabels() {
			peer.Labels[k] = v
		}
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
