// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

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
)

type CheckProvider interface {
	Name() string
	EnabledForRequest(*policystore.PolicyStore, *authz.CheckRequest) bool
	Check(*policystore.PolicyStore, *authz.CheckRequest) (*authz.CheckResponse, error)
}
