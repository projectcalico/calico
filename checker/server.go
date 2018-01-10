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
	authz "github.com/envoyproxy/data-plane-api/api/auth"

	"github.com/projectcalico/app-policy/policystore"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type (
	auth_server struct {
		NodeName string
		Store    *policystore.PolicyStore
	}
)

func NewServer(nodeName string, store *policystore.PolicyStore) *auth_server {
	return &auth_server{nodeName, store}
}

func (as *auth_server) Check(ctx context.Context, req *authz.CheckRequest) (*authz.CheckResponse, error) {
	log.Debugf("Check(%v, %v)", ctx, req)
	resp := authz.CheckResponse{Status: &status.Status{Code: code.Code_value["INTERNAL"]}}
	var st status.Status
	as.Store.Read(func(store *policystore.PolicyStore) { st = checkStore(store, req) })
	resp.Status = &st
	log.WithFields(log.Fields{
		"Request":  req,
		"Response": resp,
	}).Info("Check complete")
	return &resp, nil
}
