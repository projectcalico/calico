// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/rules"
)

// ALPCheckProvider implements CheckProvider for application layer policy (ALP)
// enforcement. It evaluates the request against the tiered network policies and
// profiles configured for the local workload endpoint.
type ALPCheckProvider struct{}

// NewALPCheckProvider returns a new ALPCheckProvider.
func NewALPCheckProvider() *ALPCheckProvider {
	return &ALPCheckProvider{}
}

func (a *ALPCheckProvider) Name() string {
	return "alp"
}

// EnabledForRequest returns true when the policy store has a local workload
// endpoint configured, which is the case in per-pod (sidecar) mode.
func (a *ALPCheckProvider) EnabledForRequest(ps *policystore.PolicyStore, _ *authz.CheckRequest) bool {
	return ps.Endpoint != nil
}

// Check evaluates the request against the configured policies and profiles
// for the local workload endpoint and returns the authorization decision.
func (a *ALPCheckProvider) Check(ps *policystore.PolicyStore, req *authz.CheckRequest) (*authz.CheckResponse, error) {
	flow := NewCheckRequestToFlowAdapter(req)
	st := checkStore(ps, ps.Endpoint, rules.RuleDirIngress, flow)
	return &authz.CheckResponse{Status: &st}, nil
}
