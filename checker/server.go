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
	"github.com/projectcalico/app-policy/policystore"

	authz "github.com/envoyproxy/data-plane-api/envoy/service/auth/v2alpha"
	"github.com/gogo/googleapis/google/rpc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type authServer struct {
	stores <-chan *policystore.PolicyStore
	Store  *policystore.PolicyStore
}

// NewServer creates a new authServer and returns a pointer to it.
func NewServer(ctx context.Context, stores <-chan *policystore.PolicyStore) *authServer {
	s := &authServer{stores, nil}
	go s.updateStores(ctx)
	return s
}

// Check applies the currently loaded policy to a network request and renders a policy decision.
func (as *authServer) Check(ctx context.Context, req *authz.CheckRequest) (*authz.CheckResponse, error) {
	log.WithFields(log.Fields{
		"context":      ctx,
		"Req.Method":   req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		"Req.Path":     req.GetAttributes().GetRequest().GetHttp().GetPath(),
		"Req.Protocol": req.GetAttributes().GetRequest().GetHttp().GetProtocol(),
	}).Info("Check start")
	resp := authz.CheckResponse{Status: &rpc.Status{Code: INTERNAL}}
	var st rpc.Status

	// Ensure that we only access as.Store once per Check call. The authServer can be updated to point to a different
	// store asynchronously with this call, so we use a local variable to reference the PolicyStore for the duration of
	// this call for consistency.
	store := as.Store
	if store == nil {
		log.Warn("Check request before synchronized to Policy, failing.")
		resp.Status.Code = UNAVAILABLE
		return &resp, nil
	}
	store.Read(func(ps *policystore.PolicyStore) { st = checkStore(ps, req) })
	resp.Status = &st
	log.WithFields(log.Fields{
		"Req.Method":   req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		"Req.Path":     req.GetAttributes().GetRequest().GetHttp().GetPath(),
		"Req.Protocol": req.GetAttributes().GetRequest().GetHttp().GetProtocol(),
		"Response":     resp,
	}).Info("Check complete")
	return &resp, nil
}

// updateStores pulls PolicyStores off the channel and assigns them.
func (as *authServer) updateStores(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		// Variable assignment is atomic, so this is threadsafe as long as each check call accesses authServer.Store
		// only once.
		case as.Store = <-as.stores:
			log.Info("Switching to new in-sync policy store.")
			continue
		}
	}
}
